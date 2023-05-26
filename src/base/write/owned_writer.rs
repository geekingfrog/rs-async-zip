use crate::{
    base::read::get_zip64_extra_field_mut,
    error::{Result, Zip64ErrorCase, ZipError},
    spec::{consts::{NON_ZIP64_MAX_NUM_FILES, NON_ZIP64_MAX_SIZE}, header::{Zip64EndOfCentralDirectoryRecord, Zip64EndOfCentralDirectoryLocator, EndOfCentralDirectoryHeader}},
    Compression, StringEncoding, ZipEntry,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::spec::extra_field::ExtraFieldAsBytes;
use crate::spec::header::{
    CentralDirectoryRecord, ExtraField, GeneralPurposeFlag, HeaderId, LocalFileHeader,
    Zip64ExtendedInformationExtraField,
};
use crc32fast::Hasher;
use futures_util::io::{AsyncWrite, AsyncWriteExt};

use super::{io::offset::AsyncOffsetWriter, CentralDirectoryEntry};

#[cfg(any(feature = "deflate", feature = "bzip2", feature = "zstd", feature = "lzma", feature = "xz"))]
use async_compression::futures::write;

pub struct ZipWriterArchive<W: AsyncWrite + Unpin> {
    writer: AsyncOffsetWriter<W>,
    cd_entries: Vec<CentralDirectoryEntry>,
    /// If true, will error if a Zip64 struct must be written.
    force_no_zip64: bool,
    /// Whether to write Zip64 end of directory structs.
    pub is_zip64: bool,
    comment_opt: Option<String>,
}

impl<W: AsyncWrite + Unpin> ZipWriterArchive<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: AsyncOffsetWriter::new(writer),
            cd_entries: Vec::new(),
            force_no_zip64: false,
            is_zip64: false,
            comment_opt: None,
        }
    }

    pub async fn write_entry_stream<E: Into<ZipEntry>>(self, entry: E) -> Result<ZipWriterEntry<W>> {
        ZipWriterEntry::from_archive(self, entry.into()).await
    }

    /// Consumes this ZIP writer and completes all closing tasks.
    ///
    /// This includes:
    /// - Writing all central directory headers.
    /// - Writing the end of central directory header.
    /// - Writing the file comment.
    ///
    /// Failure to call this function before going out of scope would result in a corrupted ZIP file.
    pub async fn close(mut self) -> Result<W> {
        let cd_offset = self.writer.offset();

        for entry in &self.cd_entries {
            self.writer.write_all(&crate::spec::consts::CDH_SIGNATURE.to_le_bytes()).await?;
            self.writer.write_all(&entry.header.as_slice()).await?;
            self.writer.write_all(entry.entry.filename().as_bytes()).await?;
            self.writer.write_all(&entry.entry.extra_fields().as_bytes()).await?;
            self.writer.write_all(entry.entry.comment().as_bytes()).await?;
        }

        let central_directory_size = (self.writer.offset() - cd_offset) as u64;
        let central_directory_size_u32 = if central_directory_size > NON_ZIP64_MAX_SIZE as u64 {
            NON_ZIP64_MAX_SIZE
        } else {
            central_directory_size as u32
        };
        let num_entries_in_directory = self.cd_entries.len() as u64;
        let num_entries_in_directory_u16 = if num_entries_in_directory > NON_ZIP64_MAX_NUM_FILES as u64 {
            NON_ZIP64_MAX_NUM_FILES
        } else {
            num_entries_in_directory as u16
        };
        let cd_offset = cd_offset as u64;
        let cd_offset_u32 = if cd_offset > NON_ZIP64_MAX_SIZE as u64 { NON_ZIP64_MAX_SIZE } else { cd_offset as u32 };

        // Add the zip64 EOCDR and EOCDL if we are in zip64 mode.
        if self.is_zip64 {
            let eocdr_offset = self.writer.offset();

            let eocdr = Zip64EndOfCentralDirectoryRecord {
                size_of_zip64_end_of_cd_record: 44,
                version_made_by: crate::spec::version::as_made_by(),
                version_needed_to_extract: 46,
                disk_number: 0,
                disk_number_start_of_cd: 0,
                num_entries_in_directory_on_disk: num_entries_in_directory,
                num_entries_in_directory,
                directory_size: central_directory_size,
                offset_of_start_of_directory: cd_offset,
            };
            self.writer.write_all(&crate::spec::consts::ZIP64_EOCDR_SIGNATURE.to_le_bytes()).await?;
            self.writer.write_all(&eocdr.as_bytes()).await?;

            let eocdl = Zip64EndOfCentralDirectoryLocator {
                number_of_disk_with_start_of_zip64_end_of_central_directory: 0,
                relative_offset: eocdr_offset as u64,
                total_number_of_disks: 1,
            };
            self.writer.write_all(&crate::spec::consts::ZIP64_EOCDL_SIGNATURE.to_le_bytes()).await?;
            self.writer.write_all(&eocdl.as_bytes()).await?;
        }

        let header = EndOfCentralDirectoryHeader {
            disk_num: 0,
            start_cent_dir_disk: 0,
            num_of_entries_disk: num_entries_in_directory_u16,
            num_of_entries: num_entries_in_directory_u16,
            size_cent_dir: central_directory_size_u32,
            cent_dir_offset: cd_offset_u32,
            file_comm_length: self.comment_opt.as_ref().map(|v| v.len() as u16).unwrap_or_default(),
        };

        self.writer.write_all(&crate::spec::consts::EOCDR_SIGNATURE.to_le_bytes()).await?;
        self.writer.write_all(&header.as_slice()).await?;
        if let Some(comment) = self.comment_opt {
            self.writer.write_all(comment.as_bytes()).await?;
        }

        Ok(self.writer.into_inner())
    }


}

pub struct ZipWriterEntry<W: AsyncWrite + Unpin> {
    writer: AsyncOffsetWriter<CompressedAsyncWriter<W>>,
    cd_entries: Vec<CentralDirectoryEntry>,
    /// If true, will error if a Zip64 struct must be written.
    force_no_zip64: bool,
    /// Whether to write Zip64 end of directory structs.
    pub is_zip64: bool,
    comment_opt: Option<String>,

    // fields specific to the ZipWriterEntry
    entry: ZipEntry,
    hasher: Hasher,
    lfh: LocalFileHeader,
    lfh_offset: usize,
    data_offset: usize,
}

impl<W: AsyncWrite + Unpin> ZipWriterEntry<W> {
    async fn from_archive(mut archive: ZipWriterArchive<W>, mut entry: ZipEntry) -> Result<Self> {
        let lfh_offset = archive.writer.offset();
        let lfh = Self::write_lfh(&mut archive, &mut entry).await?;
        let writer = archive.writer;
        let data_offset = writer.offset();

        let writer = AsyncOffsetWriter::new(CompressedAsyncWriter::from_raw(writer, entry.compression()));

        Ok(Self {
            writer,
            cd_entries: archive.cd_entries,
            force_no_zip64: archive.force_no_zip64,
            is_zip64: archive.is_zip64,
            comment_opt: archive.comment_opt,

            entry,
            hasher: Hasher::new(),
            lfh,
            lfh_offset,
            data_offset,
        })
    }

    async fn write_lfh(writer: &mut ZipWriterArchive<W>, entry: &mut ZipEntry) -> Result<LocalFileHeader> {
        // Always emit a zip64 extended field, even if we don't need it, because we *might* need it.
        // If we are forcing no zip, we will have to error later if the file is too large.
        let (lfh_compressed, lfh_uncompressed) = if !writer.force_no_zip64 {
            if !writer.is_zip64 {
                writer.is_zip64 = true;
            }
            entry.extra_fields.push(ExtraField::Zip64ExtendedInformationExtraField(
                Zip64ExtendedInformationExtraField {
                    header_id: HeaderId::Zip64ExtendedInformationExtraField,
                    data_size: 16,
                    uncompressed_size: entry.uncompressed_size,
                    compressed_size: entry.compressed_size,
                    relative_header_offset: None,
                    disk_start_number: None,
                },
            ));

            (NON_ZIP64_MAX_SIZE, NON_ZIP64_MAX_SIZE)
        } else {
            if entry.compressed_size > NON_ZIP64_MAX_SIZE as u64 || entry.uncompressed_size > NON_ZIP64_MAX_SIZE as u64
            {
                return Err(ZipError::Zip64Needed(Zip64ErrorCase::LargeFile));
            }

            (entry.compressed_size as u32, entry.uncompressed_size as u32)
        };

        let lfh = LocalFileHeader {
            compressed_size: lfh_compressed,
            uncompressed_size: lfh_uncompressed,
            compression: entry.compression().into(),
            crc: entry.crc32,
            extra_field_length: entry
                .extra_fields()
                .count_bytes()
                .try_into()
                .map_err(|_| ZipError::ExtraFieldTooLarge)?,
            file_name_length: entry.filename().as_bytes().len().try_into().map_err(|_| ZipError::FileNameTooLarge)?,
            mod_time: entry.last_modification_date().time,
            mod_date: entry.last_modification_date().date,
            version: crate::spec::version::as_needed_to_extract(entry),
            flags: GeneralPurposeFlag {
                data_descriptor: true,
                encrypted: false,
                filename_unicode: matches!(entry.filename().encoding(), StringEncoding::Utf8)
                    && matches!(entry.comment().encoding(), StringEncoding::Utf8),
            },
        };

        writer.writer.write_all(&crate::spec::consts::LFH_SIGNATURE.to_le_bytes()).await?;
        writer.writer.write_all(&lfh.as_slice()).await?;
        writer.writer.write_all(entry.filename().as_bytes()).await?;
        writer.writer.write_all(&entry.extra_fields().as_bytes()).await?;

        Ok(lfh)
    }

    pub async fn close(mut self) -> Result<ZipWriterArchive<W>> {
        self.writer.close().await?;

        let crc = self.hasher.finalize();
        let uncompressed_size = self.writer.offset() as u64;
        let mut inner_writer = self.writer.into_inner().into_inner();
        let compressed_size = (inner_writer.offset() - self.data_offset) as u64;

        let (cdr_compressed_size, cdr_uncompressed_size) = if self.force_no_zip64 {
            if uncompressed_size > NON_ZIP64_MAX_SIZE as u64 || compressed_size > NON_ZIP64_MAX_SIZE as u64 {
                return Err(ZipError::Zip64Needed(Zip64ErrorCase::LargeFile));
            }
            (uncompressed_size as u32, compressed_size as u32)
        } else {
            // When streaming an entry, we are always using a zip64 field.
            match get_zip64_extra_field_mut(&mut self.entry.extra_fields) {
                // This case shouldn't be necessary but is included for completeness.
                None => {
                    self.entry.extra_fields.push(ExtraField::Zip64ExtendedInformationExtraField(
                        Zip64ExtendedInformationExtraField {
                            header_id: HeaderId::Zip64ExtendedInformationExtraField,
                            data_size: 16,
                            uncompressed_size,
                            compressed_size,
                            relative_header_offset: None,
                            disk_start_number: None,
                        },
                    ));
                    self.lfh.extra_field_length =
                        self.entry.extra_fields().count_bytes().try_into().map_err(|_| ZipError::ExtraFieldTooLarge)?;
                }
                Some(zip64) => {
                    zip64.uncompressed_size = uncompressed_size;
                    zip64.compressed_size = compressed_size;
                }
            }

            (NON_ZIP64_MAX_SIZE, NON_ZIP64_MAX_SIZE)
        };

        inner_writer.write_all(&crate::spec::consts::DATA_DESCRIPTOR_SIGNATURE.to_le_bytes()).await?;
        inner_writer.write_all(&crc.to_le_bytes()).await?;
        inner_writer.write_all(&cdr_compressed_size.to_le_bytes()).await?;
        inner_writer.write_all(&cdr_uncompressed_size.to_le_bytes()).await?;

        let cdh = CentralDirectoryRecord {
            compressed_size: cdr_compressed_size,
            uncompressed_size: cdr_uncompressed_size,
            crc,
            v_made_by: crate::spec::version::as_made_by(),
            v_needed: self.lfh.version,
            compression: self.lfh.compression,
            extra_field_length: self.lfh.extra_field_length,
            file_name_length: self.lfh.file_name_length,
            file_comment_length: self
                .entry
                .comment()
                .as_bytes()
                .len()
                .try_into()
                .map_err(|_| ZipError::CommentTooLarge)?,
            mod_time: self.lfh.mod_time,
            mod_date: self.lfh.mod_date,
            flags: self.lfh.flags,
            disk_start: 0,
            inter_attr: self.entry.internal_file_attribute(),
            exter_attr: self.entry.external_file_attribute(),
            lh_offset: self.lfh_offset as u32,
        };

        self.cd_entries.push(CentralDirectoryEntry { header: cdh, entry: self.entry });
        // Ensure that we can fit this many files in this archive if forcing no zip64
        if self.cd_entries.len() > NON_ZIP64_MAX_NUM_FILES as usize {
            if self.force_no_zip64 {
                return Err(ZipError::Zip64Needed(Zip64ErrorCase::TooManyFiles));
            }
            if !self.is_zip64 {
                self.is_zip64 = true;
            }
        }

        Ok(ZipWriterArchive {
            writer: inner_writer,
            cd_entries: self.cd_entries,
            force_no_zip64: self.force_no_zip64,
            is_zip64: self.is_zip64,
            comment_opt: self.comment_opt,
        })
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ZipWriterEntry<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<std::result::Result<usize, std::io::Error>> {
        let poll = Pin::new(&mut self.writer).poll_write(cx, buf);

        if let Poll::Ready(Ok(written)) = poll {
            self.hasher.update(&buf[0..written]);
        }

        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_close(cx)
    }
}


// same as the original CompressedAsyncWriter but with an owned underlying writer
// instead of a mutable reference
pub enum CompressedAsyncWriter<W: AsyncWrite + Unpin> {
    Stored(ShutdownIgnoredWriter<AsyncOffsetWriter<W>>),
    #[cfg(feature = "deflate")]
    Deflate(write::DeflateEncoder<ShutdownIgnoredWriter<AsyncOffsetWriter<W>>>),
    #[cfg(feature = "bzip2")]
    Bz(write::BzEncoder<ShutdownIgnoredWriter<AsyncOffsetWriter<W>>>),
    #[cfg(feature = "lzma")]
    Lzma(write::LzmaEncoder<ShutdownIgnoredWriter<AsyncOffsetWriter<W>>>),
    #[cfg(feature = "zstd")]
    Zstd(write::ZstdEncoder<ShutdownIgnoredWriter<AsyncOffsetWriter<W>>>),
    #[cfg(feature = "xz")]
    Xz(write::XzEncoder<ShutdownIgnoredWriter<AsyncOffsetWriter<W>>>),
}

impl<W: AsyncWrite + Unpin> CompressedAsyncWriter<W> {
    pub fn from_raw(writer: AsyncOffsetWriter<W>, compression: Compression) -> Self {
        match compression {
            Compression::Stored => CompressedAsyncWriter::Stored(ShutdownIgnoredWriter(writer)),
            #[cfg(feature = "deflate")]
            Compression::Deflate => {
                CompressedAsyncWriter::Deflate(write::DeflateEncoder::new(ShutdownIgnoredWriter(writer)))
            }
            #[cfg(feature = "bzip2")]
            Compression::Bz => CompressedAsyncWriter::Bz(write::BzEncoder::new(ShutdownIgnoredWriter(writer))),
            #[cfg(feature = "lzma")]
            Compression::Lzma => CompressedAsyncWriter::Lzma(write::LzmaEncoder::new(ShutdownIgnoredWriter(writer))),
            #[cfg(feature = "zstd")]
            Compression::Zstd => CompressedAsyncWriter::Zstd(write::ZstdEncoder::new(ShutdownIgnoredWriter(writer))),
            #[cfg(feature = "xz")]
            Compression::Xz => CompressedAsyncWriter::Xz(write::XzEncoder::new(ShutdownIgnoredWriter(writer))),
        }
    }

    pub fn into_inner(self) -> AsyncOffsetWriter<W> {
        match self {
            CompressedAsyncWriter::Stored(inner) => inner.into_inner(),
            #[cfg(feature = "deflate")]
            CompressedAsyncWriter::Deflate(inner) => inner.into_inner().into_inner(),
            #[cfg(feature = "bzip2")]
            CompressedAsyncWriter::Bz(inner) => inner.into_inner().into_inner(),
            #[cfg(feature = "lzma")]
            CompressedAsyncWriter::Lzma(inner) => inner.into_inner().into_inner(),
            #[cfg(feature = "zstd")]
            CompressedAsyncWriter::Zstd(inner) => inner.into_inner().into_inner(),
            #[cfg(feature = "xz")]
            CompressedAsyncWriter::Xz(inner) => inner.into_inner().into_inner(),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CompressedAsyncWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match *self {
            CompressedAsyncWriter::Stored(ref mut inner) => Pin::new(inner).poll_write(cx, buf),
            #[cfg(feature = "deflate")]
            CompressedAsyncWriter::Deflate(ref mut inner) => Pin::new(inner).poll_write(cx, buf),
            #[cfg(feature = "bzip2")]
            CompressedAsyncWriter::Bz(ref mut inner) => Pin::new(inner).poll_write(cx, buf),
            #[cfg(feature = "lzma")]
            CompressedAsyncWriter::Lzma(ref mut inner) => Pin::new(inner).poll_write(cx, buf),
            #[cfg(feature = "zstd")]
            CompressedAsyncWriter::Zstd(ref mut inner) => Pin::new(inner).poll_write(cx, buf),
            #[cfg(feature = "xz")]
            CompressedAsyncWriter::Xz(ref mut inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::result::Result<(), std::io::Error>> {
        match *self {
            CompressedAsyncWriter::Stored(ref mut inner) => Pin::new(inner).poll_flush(cx),
            #[cfg(feature = "deflate")]
            CompressedAsyncWriter::Deflate(ref mut inner) => Pin::new(inner).poll_flush(cx),
            #[cfg(feature = "bzip2")]
            CompressedAsyncWriter::Bz(ref mut inner) => Pin::new(inner).poll_flush(cx),
            #[cfg(feature = "lzma")]
            CompressedAsyncWriter::Lzma(ref mut inner) => Pin::new(inner).poll_flush(cx),
            #[cfg(feature = "zstd")]
            CompressedAsyncWriter::Zstd(ref mut inner) => Pin::new(inner).poll_flush(cx),
            #[cfg(feature = "xz")]
            CompressedAsyncWriter::Xz(ref mut inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::result::Result<(), std::io::Error>> {
        match *self {
            CompressedAsyncWriter::Stored(ref mut inner) => Pin::new(inner).poll_close(cx),
            #[cfg(feature = "deflate")]
            CompressedAsyncWriter::Deflate(ref mut inner) => Pin::new(inner).poll_close(cx),
            #[cfg(feature = "bzip2")]
            CompressedAsyncWriter::Bz(ref mut inner) => Pin::new(inner).poll_close(cx),
            #[cfg(feature = "lzma")]
            CompressedAsyncWriter::Lzma(ref mut inner) => Pin::new(inner).poll_close(cx),
            #[cfg(feature = "zstd")]
            CompressedAsyncWriter::Zstd(ref mut inner) => Pin::new(inner).poll_close(cx),
            #[cfg(feature = "xz")]
            CompressedAsyncWriter::Xz(ref mut inner) => Pin::new(inner).poll_close(cx),
        }
    }
}

pub struct ShutdownIgnoredWriter<W: AsyncWrite + Unpin>(W);

impl<W: AsyncWrite + Unpin> ShutdownIgnoredWriter<W> {
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ShutdownIgnoredWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}
