import { GoogleGenerativeAI } from "@google/generative-ai";

const apiKey = process.env.GOOGLE_API_KEY;

const genAI = new GoogleGenerativeAI(apiKey);

const run = async () => {
  const models = await genAI.listModels();
  console.log(JSON.stringify(models, null, 2));
};

run();
