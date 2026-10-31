#!/usr/bin/env node
import { main } from "./composition/compose.js";

process.exitCode = await main(process.argv.slice(2));
