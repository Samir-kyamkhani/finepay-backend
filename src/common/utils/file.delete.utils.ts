import fs from 'fs';
import path from 'path';

type MulterFilesObject = Record<string, Express.Multer.File[]>;

function isMulterFilesObject(value: unknown): value is MulterFilesObject {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value).every(
      (item) => Array.isArray(item) && item.every((f) => 'path' in f),
    )
  );
}

function isMulterFileArray(value: unknown): value is Express.Multer.File[] {
  return (
    Array.isArray(value) &&
    value.every(
      (item) => typeof item === 'object' && item !== null && 'path' in item,
    )
  );
}

export class FileDeleteHelper {
  private static uploadsDir = path.join(process.cwd(), 'public/uploads');

  private static resolveSafePath(p?: string | null): string | null {
    if (!p) return null;

    const fullPath = path.isAbsolute(p) ? p : path.join(this.uploadsDir, p);

    // Security: ensure no path escape
    if (!fullPath.startsWith(this.uploadsDir)) return null;

    return fullPath;
  }

  static deleteUploadedImages(
    input:
      | string
      | string[]
      | Express.Multer.File
      | Express.Multer.File[]
      | MulterFilesObject
      | null
      | undefined,
  ): void {
    if (!input) return;

    const paths: string[] = [];

    if (typeof input === 'string') {
      paths.push(input);
    } else if (
      Array.isArray(input) &&
      input.every((i) => typeof i === 'string')
    ) {
      paths.push(...input);
    } else if (Array.isArray(input) && isMulterFileArray(input)) {
      input.forEach((file) => file?.path && paths.push(file.path));
    }
    //  NEW: handle single Multer file
    else if (typeof (input as Express.Multer.File).path === 'string') {
      paths.push((input as Express.Multer.File).path);
    } else if (isMulterFilesObject(input)) {
      Object.values(input).forEach((fileList) => {
        fileList.forEach((file) => file?.path && paths.push(file.path));
      });
    }

    for (const p of paths) {
      const safePath = this.resolveSafePath(p);
      if (!safePath) continue;

      try {
        if (fs.existsSync(safePath)) {
          fs.unlinkSync(safePath);
          console.log('🗑️ Deleted:', safePath);
        }
      } catch (err) {
        console.error('❌ Error deleting file:', err);
      }
    }
  }
}

//use
// FileDeleteHelper.deleteUploadedImages(files);
