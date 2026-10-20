/** Reads QR codes from images and from the camera, with the jsQR decoder. Nothing leaves the browser. */
import jsQR from 'jsqr';

/**
 * Reads the QR code in an image.
 *
 * @param image - A bitmap, a canvas image source or a video frame source with a size.
 * @param width - The width of the image in pixels.
 * @param height - The height of the image in pixels.
 * @returns The text of the code, or an empty string when there is no readable code.
 */
export function decodeImage(image: CanvasImageSource, width: number, height: number): string {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;

  const context = canvas.getContext('2d', { willReadFrequently: true });
  if (!context) {
    return '';
  }

  context.drawImage(image, 0, 0, width, height);
  const pixels = context.getImageData(0, 0, width, height);

  return jsQR(pixels.data, width, height)?.data ?? '';
}

/**
 * Reads the QR code in a picture file, such as a screenshot.
 *
 * @param file - The image that the person chose.
 * @returns The text of the code.
 * @throws Error if the file is not an image or holds no readable code.
 */
export async function decodeFile(file: File): Promise<string> {
  const bitmap = await createImageBitmap(file);
  try {
    const text = decodeImage(bitmap, bitmap.width, bitmap.height);
    if (!text) {
      throw new Error('No QR code was found in the image.');
    }

    return text;
  } finally {
    bitmap.close();
  }
}
