import mongoose from "mongoose";

const connectDb= async ()=>{
    //event name
    mongoose.connection.on('connected', ()=>console.log("Database connected"));

    await mongoose.connect(`${process.env.MONGODB_URL}/mern-2fa`);
}
export default connectDb;