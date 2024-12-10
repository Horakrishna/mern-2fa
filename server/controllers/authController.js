import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from "../config/emailTemplate.js";
import transporter from '../config/nodemailer.js';
import userModel from '../models/useModel.js';

//Register Function
export const register = async(req,res)=>{

    const {name, email, password} =req.body;
    //any field isMissing
    if (!name || !email || !password) {
        return res.json({
            success:false,
            message:"Missing Details"
        })
    }

    //store user data on Mongodb 
    try {
       //user Allready exist
        const existingUser =await userModel.findOne({email});
        if (existingUser) {

            return res.json({
                success:false,
                message:"user already exists"
            })
        }
        //encripte password
        const hashedPassword =await bcrypt.hash(password, 10);
        //create new User
        const user = new userModel({name, email, password:hashedPassword})
       
        await user.save();
        
     
        //Generate token with cookies
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET,{expiresIn: '7d'});
        //useing cookie send the token

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', //secure willl be false
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', //when it is run Online
            maxAge: 7 * 24 * 60 * 60 * 1000 //time converted with milisecond..Expire time for cookies

        });
        //Wellcom Email sender code
        const mailOptions ={
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Wellcome to our world",
            text:`heloo dunia . your email id is : ${email}`
        }
        
        await transporter.sendMail(mailOptions);

        res.status(201).json({
            success: true,
            message: "User registered successfully",
        });
      
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
}

export const login = async (req,res)=>{
    const {email, password} =req.body;

    //validate Email and password
    if ( !email || !password ) {
        return res.json({
            success:false,
            message:"Email and Password are Required"
        }) 
    }

    //
    try {
        //user is available

        const user = await userModel.findOne({email});
        if (!user) {
            return res.json({
                success:false,
                message:" invalid Email"
            })   
        }
        //When Password match
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({
                success:false,
                message:" Incorrect Password"
            })
        }

        //generate token when email and password is exist
        const token = jwt.sign( {id: user._id } , process.env.JWT_SECRET,{expiresIn: '7d'} )
        //useing cookie send the token

        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production', //secure willl be false
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', //when it is run Online
            maxAge: 7 * 24 * 60 * 60 * 1000 //time converted with milisecond..Expire time for cookies

        });

        
        //user bSuccessfully Loged in

        return res.json({
             success:true,
             message:"User successfully login"
        })

    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
}

//Logout function

export const logout =async (req,res)=>{

    try {
        //clear cookies
        res.clearCookie('token',{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        })
        return res.json({
            success:true,
            message:"User successfully Logout"
        })
        
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        }) 
    }
}

//Email verification OTP to the Users's Email

export const sendVerifyOtp = async (req,res) =>{
    try {
        
        const { userId } =req.body;
        
        const user =await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.json({
                success:false,
                message:"Account Already verified"
            })
        }

        //save n otp in db
        const otp =  String(Math.floor(100000 + Math.random() * 900000));
       //Generate 6 degit otp
        user.verifyOtp = otp;
        //Verify otp expires
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000
        //propertity value save
        await user.save();

        const mailOptions ={
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
           // text:`Your otp is ${otp} : Verify your account using this OTP.`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}",user.email)
        }

        await transporter.sendMail(mailOptions);

        res.json({
            success: true,
            message:'Verification OTP Sent on Email'
        })

    } catch (error) {
        res.json({
            success:false,
            message:error.message
        }) 
    }
}
//Email Verification

export const verifyEmail = async (req,res) =>{
    const { userId, otp } =req.body;

    if (!userId || !otp ) {

        return res.json({
            success:false,
            message:"Missing Details"
        })
    }

    try {
        //find the user from userId
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({
                success:false,
                message:"User not found"
            })
        }
        if ( user.verifyOtp === '' || user.verifyOtp !== otp ) {
            return res.json({
                success:false,
                message:"Invalid otp"
            })
        }
        //otp is valid .then we check expiry date
        if ( user.verifyOtpExpireAt < Date.now()) {
            return res.json({
                success:false,
                message:"Otp expired"
            })
        }
        //otp expire date after the current date.otp is not expire
        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();

        return res.json({
            success:true,
            message:"Email verified sussfully"
        })


    } catch (error) {
        res.json({
            success:false,
            message:error.message
        }) 
    }
} 
//Check user is Authenticate
export const isAuthenticate = async (req,res)=>{

    try {
        return res.json({
            success:true,
            message:"User already  Authenticated"
        })
        
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        }) 
    }
}
//Send password reset OTP

export const sendResetOtp =async (req,res)=>{
    const { email } =req.body;

    if( !email ){
        return res.json({
            success:false,
            message:"Email is required"
        })
    }
    try {
        const user = await userModel.findOne({email});

        if (!user) {
            return res.json({
                success:false,
                message:"User not found"
            })
        }
         //save  otp in db
         const otp =  String(Math.floor(100000 + Math.random() * 900000));
         //Generate 6 degit otp
          user.resetOtp = otp;
          user.resetOtpExpireAt = Date.now() + 15  * 60 * 1000 // 15 minutes time in milisecond
          await user.save();
  
          const mailOptions ={
              from: process.env.SENDER_EMAIL,
              to: user.email,
              subject: "Password Reset OTP",
             // text:`Your otp for reset your password is ${otp} : Your password reset using this OTP.`
             html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}",user.email)

          };
  
          await transporter.sendMail(mailOptions);
          return res.json({
            success:true,
            message:"OTP sent to Your email"
          });
        
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
}
//User Reset user Password
export const resetPassword = async(req,res)=>{
    const { email, otp, newPassword } =req.body;

    if (!email || !otp || !newPassword ) {
        return res.json({
            success:false,
            message:"OTP, New password and email is required"
          });
    }

     try {
        
        const user = await userModel.findOne({email});

        if (!user) {
           return res.json({
            success:false,
            message:"User not Found"
          }); 
        }
        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({
                success:false,
                message:"Invalid OTP"
              }); 
        }
        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({
                success:false,
                message:"OTP Expired"
              });   
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password =hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({
            success:true,
            message:"Password has been reset successfully"
          }); 

     } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
     }
}