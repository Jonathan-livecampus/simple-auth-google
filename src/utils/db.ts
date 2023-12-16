import mongoose from "mongoose";

const db = async () => {
  if (mongoose.connections[0].readyState) return;

  if (!process.env.MONGO_URI) throw new Error("Mongo URL not found");

  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Mongo Connection successfully established.");
  } catch (error) {
    throw new Error("Error connecting to Mongoose");
  }
};

export default db;
