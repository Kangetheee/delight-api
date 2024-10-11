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

// token ID
const createToken = (id) => {
    const secret = process.env.JWT_SECRET;
    console.log("Creating token with secret:", secret);  // Debug line 6
    return jwt.sign({ id }, secret);
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

export { loginUser, registerUser };
