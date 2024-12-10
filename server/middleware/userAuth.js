import jwt from 'jsonwebtoken';

//next execute the conmtroller function
const userAuth = async (req,res,next)=>{
    const { token } =req.cookies;

    if (!token) {
        return res.json({
            success:false,
            message:"Not Authorized.Login Again"
        })
    }
    try {
        //decode the token
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (tokenDecode.id) {
            req.body.userId =tokenDecode.id

        }else{
            res.json({
            success:false,
            message:"Not Authorized.Login Again"
            })
        }
        next();

    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })  
    }
}

export default userAuth;