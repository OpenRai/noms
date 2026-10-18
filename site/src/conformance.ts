import * as api from '@openrai/noms';
// This entry is separate from the playground and shares its crypto bundle.
// @ts-expect-error Test-only portable JavaScript adapter has no declaration file.
import { runCase } from '../../scripts/lib/conformance.mjs';
Object.assign(window, { runConformanceCase: (test: unknown) => runCase(api, test) });
