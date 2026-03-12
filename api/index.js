// Vercel Serverless Function entry point
// This re-exports the Express app from server/index.js
// Vercel detects this and runs it as a serverless function
export { default } from '../server/index.js';
