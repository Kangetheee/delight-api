import mongoose from "mongoose"
import "dotenv/config"

const db = process.env.MONGOURL

export const connectDB = async() => {
    await mongoose.connect(db).then(() => console.log("DB Connected")
    )
}




