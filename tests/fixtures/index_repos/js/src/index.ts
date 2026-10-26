import x from './util';
import { a, b } from "./lib/math";
import type { T } from './types';
import * as fs from 'fs';
import path from 'node:path';
import React from 'react';
import { S3Client } from '@aws-sdk/client-s3';
export * from './reexport';
export { y } from './lib';
// import fake from 'commented';
/* import gone from 'block';
   import gone2 from 'block2'; */
const s = "import nope from 'string'";
const lazy = import('./lazy');
import './side-effect.css';
import cfg from '@/config';
import esm from './esm.js';
import {
  m1,
  m2,
} from './multi';
import uni from './ünïcode';
import missing from './does-not-exist';
const re = /import x from 'regex'/;
