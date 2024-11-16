import userModel from "../models/userModel.js";
import jwt from 'jsonwebtoken';
import bcrypt from "bcrypt";
import validator from "validator";

const loginUser = async (req, res) => {
    const { email, password } = req.body;
    try {
        console.log("Login request received with email:", email);  // Debug line 1
        const user = await userModel.findOne({ email });
        
        // user existence
        if (!user) {
            console.log("User does not exist");  // Debug line 2
            return res.json({ success: false, message: "User Doesn't Exist" });
        }
        
        console.log("User found:", user.email);  // Debug line 3
        // password comparison
        const isMatch = await bcrypt.compare(password, user.password);
        console.log("Password match status:", isMatch);  // Debug line 4
        if (!isMatch) {
            return res.json({ success: false, message: "Invalid Credentials" });
        }

        const token = createToken(user._id);
        res.json({ success: true, token });

    } catch (error) {
        console.log("Error during login:", error);  // Debug line 5
        res.json({ success: false, message: "Error" });
    }
};

// Token creation function
const createToken = (id) => {
    const secret = process.env.JWT_SECRET;
    const expiresIn = "1h"; // Token expires in 1 hour
    return jwt.sign({ id }, secret, { expiresIn });
};

// Google Login Function
const googleLogin = async (req, res) => {
    const { uid, name, email } = req.body;

    try {
        // Check if the user already exists in the database
        let user = await userModel.findOne({ email });

        if (!user) {
            // Create a new user if not found
            user = new userModel({
                uid,
                name,
                email,
                password: null, // Google users don't have passwords
            });

            await user.save();
        }

        // Create a JWT token for the user
        const token = createToken(user._id);

        res.status(200).json({ success: true, token });
    } catch (error) {
        console.error("Error during Google login:", error);
        res.status(500).json({ success: false, message: "An internal server error occurred." });
    }
};

const registerUser = async (req, res) => {
    const { name, password, email } = req.body;
    try {
        console.log("Register request received:", email);  // Debug line 7
        // user existence
        const exists = await userModel.findOne({ email });
        if (exists) {
            return res.json({ success: false, message: "User Exists." });
        }
        
        // email format validity
        if (!validator.isEmail(email)) {
            return res.json({ success: false, message: "Please enter a Valid Email." });
        }
        
        // password length
        if (password.length < 8) {
            return res.json({ success: false, message: "Please enter a Stronger Password" });
        }

        // Hashing Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save the user with hashed password
        const newUser = new userModel({
            name: name,
            email: email,
            password: hashedPassword  
        });
        

        const user = await newUser.save();
        const token = createToken(user._id);
        res.json({ success: true, token });

    } catch (error) {
        console.log("Error during registration:", error);  // Debug line 8
        res.json({ success: false, message: "Error" });
    }
};

export { loginUser, registerUser, googleLogin };
