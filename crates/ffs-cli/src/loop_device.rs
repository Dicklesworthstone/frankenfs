//! Validate and retain caller-owned whole-image loop devices for FUSE mounts.

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, bail};
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[derive(Debug)]
pub struct BorrowedLoopDevice {
    // Keep the borrowed association referenced for the entire mount lifecycle,
    // including an autoclear loop whose caller has closed its own descriptor.
    _device: File,
    fsname: String,
}

impl BorrowedLoopDevice {
    #[must_use]
    pub fn fsname(&self) -> &str {
        &self.fsname
    }
}

#[cfg(target_os = "linux")]
fn validate_loop_backing_file(
    image_metadata: &std::fs::Metadata,
    backing_file: &Path,
    offset: u64,
    sizelimit: u64,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if offset != 0 || sizelimit != 0 {
        bail!(
            "--fuseblk-device requires the entire image: loop offset={offset}, sizelimit={sizelimit}; both must be zero"
        );
    }
    let backing_metadata = std::fs::metadata(backing_file).with_context(|| {
        format!(
            "failed to inspect loop backing file {}",
            backing_file.display()
        )
    })?;
    if !backing_metadata.is_file()
        || image_metadata.dev() != backing_metadata.dev()
        || image_metadata.ino() != backing_metadata.ino()
    {
        bail!("--fuseblk-device does not map the supplied regular image");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn loop_backing_path(backing_bytes: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    // Linux loop_attr_backing_file_show emits raw file_path bytes plus one
    // newline, without escaping. Preserve literal backslashes, whitespace,
    // newlines in the filename, and non-UTF-8 bytes.
    let backing_bytes = backing_bytes
        .strip_suffix(b"\n")
        .context("loop backing_file is missing its sysfs newline delimiter")?;
    let backing_file = PathBuf::from(std::ffi::OsString::from_vec(backing_bytes.to_vec()));
    if !backing_file.is_absolute() {
        bail!("loop backing_file must identify an attached absolute image path");
    }
    Ok(backing_file)
}

#[cfg(target_os = "linux")]
pub fn validate_borrowed_loop_device(
    image_path: &Path,
    device_path: &Path,
) -> Result<BorrowedLoopDevice> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

    let image = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(image_path)
        .with_context(|| format!("failed to open image {}", image_path.display()))?;
    let image_metadata = image
        .metadata()
        .context("failed to inspect supplied image")?;
    if !image_metadata.is_file() {
        bail!("--fuseblk-device requires a regular image file");
    }

    let canonical_device = std::fs::canonicalize(device_path).with_context(|| {
        format!(
            "failed to resolve --fuseblk-device {}",
            device_path.display()
        )
    })?;
    let device = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&canonical_device)
        .with_context(|| {
            format!(
                "failed to open borrowed loop device {}",
                canonical_device.display()
            )
        })?;
    let device_metadata = device
        .metadata()
        .context("failed to inspect borrowed loop device")?;
    if !device_metadata.file_type().is_block_device() {
        bail!("--fuseblk-device must name a loop block device");
    }
    let sysfs_loop = PathBuf::from(format!(
        "/sys/dev/block/{}:{}/loop",
        nix::sys::stat::major(device_metadata.rdev()),
        nix::sys::stat::minor(device_metadata.rdev()),
    ));
    let read_loop_u64 = |name: &str| -> Result<u64> {
        std::fs::read_to_string(sysfs_loop.join(name))
            .with_context(|| {
                format!(
                    "--fuseblk-device must be an attached whole loop device; failed to read {name} at {}",
                    sysfs_loop.display()
                )
            })?
            .trim()
            .parse()
            .with_context(|| format!("invalid loop {name} in {}", sysfs_loop.display()))
    };
    let offset = read_loop_u64("offset")?;
    let sizelimit = read_loop_u64("sizelimit")?;
    let backing_bytes = std::fs::read(sysfs_loop.join("backing_file"))
        .context("failed to read loop backing_file")?;
    let backing_file = loop_backing_path(&backing_bytes)?;
    validate_loop_backing_file(&image_metadata, &backing_file, offset, sizelimit)?;
    let fsname = canonical_device
        .to_str()
        .context("--fuseblk-device path must be valid UTF-8 for FUSE fsname")?
        .to_owned();
    Ok(BorrowedLoopDevice {
        _device: device,
        fsname,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn validate_borrowed_loop_device(
    _image_path: &Path,
    _device_path: &Path,
) -> Result<BorrowedLoopDevice> {
    bail!("--fuseblk-device requires Linux loop devices");
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn borrowed_loop_device_rejects_regular_file_and_non_regular_image() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let image = directory.path().join("image");
        std::fs::write(&image, b"image").expect("regular image");
        let error = super::validate_borrowed_loop_device(&image, &image)
            .expect_err("a regular file must not select fuseblk");
        assert!(error.to_string().contains("loop block device"));
        let error = super::validate_borrowed_loop_device(directory.path(), &image)
            .expect_err("the image itself must be regular");
        assert!(error.to_string().contains("regular image file"));
    }

    #[test]
    fn loop_backing_validation_accepts_identity_and_rejects_wrong_or_partial_images() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let image = directory.path().join("image");
        let alias = directory.path().join("hard-linked image");
        let other = directory.path().join("different image");
        std::fs::write(&image, b"image").expect("regular image");
        std::fs::hard_link(&image, &alias).expect("image hard link");
        std::fs::write(&other, b"image").expect("different inode with identical contents");
        let image_metadata = std::fs::metadata(&image).expect("image metadata");
        super::validate_loop_backing_file(&image_metadata, &alias, 0, 0)
            .expect("a hard link identifies the same whole image");
        let error = super::validate_loop_backing_file(&image_metadata, &other, 0, 0)
            .expect_err("identical contents cannot substitute for image identity");
        assert!(error.to_string().contains("does not map"));
        for (offset, sizelimit) in [(512, 0), (0, 4096), (512, 4096)] {
            let error =
                super::validate_loop_backing_file(&image_metadata, &alias, offset, sizelimit)
                    .expect_err("partial image mappings must be rejected");
            assert!(error.to_string().contains("both must be zero"));
        }
    }

    #[test]
    fn loop_backing_path_preserves_raw_bytes_and_only_removes_sysfs_delimiter() {
        use std::os::unix::ffi::OsStrExt;

        let path = super::loop_backing_path(b"/tmp/image \\040\t\xff\n\n")
            .expect("kernel raw path bytes should parse");
        assert_eq!(path.as_os_str().as_bytes(), b"/tmp/image \\040\t\xff\n");
        for invalid in [b"".as_slice(), b"\n", b"relative\n", b"/no-delimiter"] {
            assert!(super::loop_backing_path(invalid).is_err());
        }
    }
}
