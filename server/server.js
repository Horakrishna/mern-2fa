import cookieParser from 'cookie-parser';
import cors from 'cors';
import 'dotenv/config';
import express from 'express';
import connectDb from './config/mongodb.js';
import authRouter from './routes/authRoute.js';
import userRouter from './routes/userRoute.js';



const app =express();
const port =process.env.PORT || 4000
connectDb();
//Linkup To bankend to frontend
const allowedOrigin = ["http://localhost:5173"]
app.use(express.json());
app.use(cookieParser());
//
app.use(cors({origin:allowedOrigin, credentials:true}));

//api end point
app.get('/',(req, res) =>res.send("Api is Working"));
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.listen(port, ()=>console.log(`Server started on PORT :${port}`));
