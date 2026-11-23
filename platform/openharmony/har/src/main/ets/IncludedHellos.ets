import { fileIo } from '@kit.CoreFileKit';
import { resourceManager } from '@kit.LocalizationKit';

const MAX_FILES: number = 1024;
const MAX_FILE_BYTES: number = 65535;
const MAX_TOTAL_BYTES: number = 4 * 1024 * 1024;
const INDEX_ROW_BYTES: number = 11;

/** Installs explicitly packaged trusted HELLO resources before starting a node. */
export class IncludedHellos {
  /**
   * The parent is an existing absolute app-private directory, such as filesDir.
   * A successful result is a new immutable generation containing hellos/.
   * Retain it until every node using bootstrapDataDir has closed. Installing
   * another generation never mutates or removes an earlier generation.
   */
  static async install(manager: resourceManager.ResourceManager, parentDirectory: string): Promise<string> {
    if (!parentDirectory.startsWith('/') || parentDirectory.indexOf('\0') >= 0) {
      throw new Error('Included HELLO parent must be an absolute app-private directory');
    }
    const parent = await fileIo.lstat(parentDirectory);
    if (!parent.isDirectory()) {
      throw new Error('Included HELLO parent must be an existing ordinary directory');
    }
    const index = await manager.getRawFileContent('gnunet/hellos.list');
    const names = IncludedHellos.names(index);
    const generation = await fileIo.mkdtemp(`${parentDirectory}/gnunet-hellos-XXXXXX`);
    try {
      await fileIo.mkdir(`${generation}/hellos`);
      let total: number = 0;
      for (const name of names) {
        const body = await manager.getRawFileContent(`gnunet/hellos/${name}`);
        if (body.byteLength === 0 || body.byteLength > MAX_FILE_BYTES ||
          total + body.byteLength > MAX_TOTAL_BYTES) {
          throw new Error('Packaged included HELLO byte budget exceeded');
        }
        total += body.byteLength;
        await IncludedHellos.write(`${generation}/hellos/${name}`, body);
      }
      // Only this completed directory is returned to the caller's NodeOptions.
      return generation;
    } catch (cause) {
      const original = cause as Error;
      try {
        await fileIo.rmdir(generation);
      } catch (cleanup) {
        throw new Error(`${original.message}; included HELLO cleanup: ${(cleanup as Error).message}`);
      }
      throw original;
    }
  }

  private static names(index: Uint8Array): string[] {
    if (index.byteLength === 0 || index.byteLength > MAX_FILES * INDEX_ROW_BYTES ||
      index.byteLength % INDEX_ROW_BYTES !== 0) {
      throw new Error('Invalid packaged included HELLO index');
    }
    const names: string[] = [];
    for (let start: number = 0; start < index.byteLength; start += INDEX_ROW_BYTES) {
      let name: string = '';
      let ordinal: number = 0;
      for (let digit: number = 0; digit < 4; digit++) {
        const value = index[start + digit];
        if (value < 48 || value > 57) {
          throw new Error('Invalid packaged included HELLO filename');
        }
        name += String.fromCharCode(value);
        ordinal = ordinal * 10 + value - 48;
      }
      const suffix: number[] = [46, 104, 101, 108, 108, 111, 10];
      for (let position: number = 0; position < suffix.length; position++) {
        if (index[start + 4 + position] !== suffix[position]) {
          throw new Error('Invalid packaged included HELLO index line');
        }
      }
      name += '.hello';
      if (ordinal !== start / INDEX_ROW_BYTES) {
        throw new Error('Included HELLO index must be consecutive from 0000');
      }
      names.push(name);
    }
    return names;
  }

  private static async write(path: string, body: Uint8Array): Promise<void> {
    // The fresh private generation has no previous file or shared path owner.
    const file = await fileIo.open(path, fileIo.OpenMode.CREATE | fileIo.OpenMode.WRITE_ONLY);
    let failure: Error | undefined = undefined;
    try {
      // Resource views may have a byte offset; write only this complete body.
      const owned = new Uint8Array(body.byteLength);
      owned.set(body);
      const written = await fileIo.write(file.fd, owned.buffer);
      if (written !== body.byteLength) {
        throw new Error('Included HELLO file write was incomplete');
      }
      await fileIo.fsync(file.fd);
    } catch (cause) {
      failure = cause as Error;
    }
    try {
      await fileIo.close(file);
    } catch (cause) {
      const close = cause as Error;
      throw new Error(failure === undefined ? close.message :
        `${failure.message}; included HELLO close: ${close.message}`);
    }
    if (failure !== undefined) {
      throw failure;
    }
  }
}
