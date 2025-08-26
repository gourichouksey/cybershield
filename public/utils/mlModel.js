// Optional TF.js model loader & predictor. If @tensorflow/tfjs-node is not installed or model missing,
// predict() will throw. Caller should catch and fallback to heuristic.
const path = require('path');

let tf = null;
let model = null;
let modelLoaded = false;

async function tryLoadTf() {
  if (tf) return tf;
  try {
    tf = require('@tensorflow/tfjs-node');
    return tf;
  } catch (err) {
    throw new Error('tfjs-node not installed');
  }
}

async function loadModel() {
  if (modelLoaded) return model;
  await tryLoadTf();
  const modelPath = 'file://' + path.join(__dirname, '..', 'model', 'model.json');
  try {
    model = await tf.loadLayersModel(modelPath);
    modelLoaded = true;
    console.log('ML model loaded from', modelPath);
    return model;
  } catch (err) {
    throw new Error('Failed to load model: ' + err.message);
  }
}

/**
 * features: Array<number> e.g. [suspiciousCount, hasCert, packageSimilarity, sizeMBNormalized]
 * returns { probability: 0..1 }
 */
async function predict(features) {
  await loadModel();
  const input = tf.tensor2d([features], [1, features.length], 'float32');
  const out = model.predict(input);
  const data = await out.data();
  let prob = 0;
  if (data.length === 1) prob = data[0];
  else prob = data[data.length - 1];
  prob = Math.max(0, Math.min(1, prob));
  return { probability: prob };
}

module.exports = { loadModel, predict };