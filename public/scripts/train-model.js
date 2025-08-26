/**
 * Simple trainer that generates synthetic examples and saves a TF.js model to ./model.
 * NOTE: requires @tensorflow/tfjs-node to be installed:
 *   npm install @tensorflow/tfjs-node --save
 *
 * Run:
 *   npm run train-model
 */
const tf = (() => {
  try { return require('@tensorflow/tfjs-node'); }
  catch (err) { console.error('Please install @tensorflow/tfjs-node first.'); process.exit(1); }
})();
const fs = require('fs');
const path = require('path');

function generateExample() {
  const suspiciousCount = Math.floor(Math.random() * 7);
  const hasCert = Math.random() > 0.25 ? 1 : 0;
  const packageSimilarity = Math.random();
  const sizeMBNormalized = Math.random() * 2;
  let score = 0;
  score += Math.min(1, suspiciousCount * 0.12);
  score += hasCert ? 0 : 0.3;
  score += (1 - packageSimilarity) * 0.25;
  if (sizeMBNormalized < 0.01) score += 0.15;
  const prob = Math.max(0, Math.min(1, score));
  const label = prob > 0.5 ? 1 : 0;
  return { x: [suspiciousCount, hasCert, packageSimilarity, sizeMBNormalized], y: label };
}

async function generateDataset(n = 3000) {
  const X = []; const Y = [];
  for (let i = 0; i < n; i++) { const ex = generateExample(); X.push(ex.x); Y.push(ex.y); }
  const xs = tf.tensor2d(X); const ys = tf.tensor2d(Y, [Y.length, 1]);
  return { xs, ys };
}

async function train() {
  const { xs, ys } = await generateDataset();
  const model = tf.sequential();
  model.add(tf.layers.dense({ inputShape: [4], units: 16, activation: 'relu' }));
  model.add(tf.layers.dropout({ rate: 0.2 }));
  model.add(tf.layers.dense({ units: 8, activation: 'relu' }));
  model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));
  model.compile({ optimizer: tf.train.adam(0.001), loss: 'binaryCrossentropy', metrics: ['accuracy'] });

  console.log('Training...');
  await model.fit(xs, ys, { epochs: 30, batchSize: 64, validationSplit: 0.12 });
  const outDir = path.join(__dirname, '..', 'model');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  await model.save('file://' + outDir);
  console.log('Saved model to', outDir);
  xs.dispose(); ys.dispose(); tf.disposeVariables();
}

train().catch(err => { console.error('Training failed:', err); process.exit(1); });