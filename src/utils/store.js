import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const dataDirectory = path.resolve(directory, '../../data');

export async function read(name) {
  const file = path.join(
    dataDirectory,
    `${name}.json`,
  );

  try {
    const content = await fs.readFile(file, 'utf8');
    return JSON.parse(content);
  } catch {
    return [];
  }
}

export async function write(name, value) {
  const file = path.join(
    dataDirectory,
    `${name}.json`,
  );

  await fs.mkdir(dataDirectory, {
    recursive: true,
  });

  await fs.writeFile(
    file,
    JSON.stringify(value, null, 2),
    'utf8',
  );
}
