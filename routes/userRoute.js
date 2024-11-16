import express from "express"
import { loginUser, registerUser, googleLogin } from "../controllers/userController.js"

const userRouter = express.Router()

userRouter.post("/login", loginUser)
userRouter.post("/register", registerUser)
userRouter.post("/google-login", googleLogin); 

export default userRouter;