import axios from 'axios';
import React, { useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { assets } from '../assets/assets';
import { AppContext } from '../context/AppContext';

const Login = () => {
  const { backendUrl,setIsLoggedin,getUserData } =useContext(AppContext)
  const [state, setState] =useState('Sign Up');

  const [name,setName] =useState('')
  const [email,setEmail] =useState('')
  const [password,setPassword] =useState('')

  const navigate =useNavigate();
  const onSubmitHandler = async (e)=>{
    try {
      e.preventDefault();
      axios.defaults.withCredentials =true

      if (state === "Sign Up") {
        //register api call
       const  { data } = await axios.post(backendUrl + '/api/auth/register', {name,email,password});
       if(data.success){
        setIsLoggedin(true)
        getUserData()
        navigate('/')
       }else{
        toast.error(data.message)
       }
      }else{
        //Login Api call
        const  { data } = await axios.post(backendUrl + '/api/auth/login', {email,password});
        if(data.success){
         setIsLoggedin(true)
         getUserData()
         navigate('/')
        }else{
         toast.error(data.message)
        }
      }
    } catch (error) {
      toast.error(error.message)
    }
  }
  return (
    <div className='flex items-center justify-center min-h-screen px-6 sm:px-0 bg-gradient-to-br from-blue-200 to-purple-400'>
        <img onClick={()=>navigate('/')} src={assets.logo} className='absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer' alt="" />
        <div className='bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-500 text-sm'>
          <h2 className='text-3xl font-semibold text-white text-center mb-3'>{ state === "Sign Up" ? "Create  Account" : 'Login' }</h2>
          <p className='text-center text-sm mb-6'>{ state === "Sign Up" ? "Create your Account" : 'Login to your account' }</p>
          <form onSubmit={onSubmitHandler}>
            {
              state === "Sign Up" && (
                <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]'> 
                <img src={assets.person_icon} alt="" />
                <input onChange={(e)=>setName(e.target.value)} value={name} className='bg-transparent outline-none' type="text" placeholder='Your Name' required />
              </div>
              )
            }
            
            <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]'> 
              <img src={assets.person_icon} alt="" />
              <input onChange={(e)=>setEmail(e.target.value)} value={email} className='bg-transparent outline-none' type="email" placeholder='Your Email' required />
            </div>
            <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]'> 
              <img src={assets.lock_icon} alt="" />
              <input onChange={(e)=>setPassword(e.target.value)} value={password} className='bg-transparent outline-none' type="password" placeholder='Your Password' required />
            </div>
            <p onClick={()=>navigate('/reset-password')} className='mb-4 text-indigo-500 cursor-pointer'>Forget Password</p>
          <button className='w-full py-2.5 rounded-full bg-gradient-to-r from-indigo-500 to-indigo-900 text-white font-medium'>{state}</button>
          </form>

          { state === "Sign Up" ? ( <p className='text-center text-sm text-gray-400 mt-4'>Already Have an Account ? { ' ' }
            <span onClick={()=>setState("Login")} className='text-blue-400 cursor-pointer underline'>Login Here</span>
          </p>) 
          
          : (  <p className='text-center text-sm text-gray-400 mt-4'>Don't Have an Account ? { ' ' }
            <span onClick={()=>setState("Sign Up")} className='text-blue-400 cursor-pointer underline'>Signup Here</span>
          </p>)}
        
        </div>
    </div>
  )
}

export default Login