#!/usr/bin/env node
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const libraryEntry = fileURLToPath(import.meta.resolve('@openrai/noms'));
const cliEntry = pathToFileURL(join(dirname(libraryEntry), 'cli.js'));
await import(cliEntry.href);
