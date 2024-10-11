import orderModel from "../models/orderModel.js";
import userModel from "../models/userModel.js";
import Stripe from "stripe";
import PayHero from 'payhero-wrapper';
import axios from 'axios';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const payHero_user = process.env.PAYHERO_USER_KEY;
const payHero_pass = process.env.PAYHERO_SECRET_KEY;

// Placing user order for frontend
const placeOrder = async (req, res) => {
    const frontend_url = "http://localhost:5173";

    // Your API username and password
    const apiUsername = process.env.PAYHERO_USER_KEY; // Use environment variables for security
    const apiPassword = process.env.PAYHERO_SECRET_KEY;

    // Concatenating username and password with colon
    const credentials = `${apiUsername}:${apiPassword}`;

    // Base64 encode the credentials
    const encodedCredentials = Buffer.from(credentials).toString('base64');

    // Creating the Basic Auth token
    const basicAuthToken = `Basic ${encodedCredentials}`;
    console.log(basicAuthToken)
    const payHero = new PayHero(basicAuthToken); // Initialize PayHero with the Basic Auth token

    try {
        const { userId, items, amount, address, phone } = req.body;

        // Validate input data
        if (!userId || !items || items.length === 0 || !amount || !address) {
            return res.status(400).json({ success: false, message: "Invalid order data" });
        }

        // Create a new order
        const newOrder = new orderModel({
            userId,
            items,
            amount,
            address,
            phone,
        });
        await newOrder.save();

        // Clear user's cart
        await userModel.findByIdAndUpdate(userId, { cartData: {} });

        // Calculate total amount for the items
        const totalAmount = items.reduce((acc, item) => acc + item.price * item.quantity, 0);
        console.log(totalAmount)
        // Add delivery charges
        const deliveryCharge = 2 * 100; // Adjust delivery charge as needed
        const finalAmount = totalAmount + deliveryCharge; // Final amount including delivery charges
        console.log(finalAmount)
        // Prepare payment details for PayHero
        const paymentDetails = {
            amount: finalAmount, // Total amount including delivery charges
            phone_number: phone, // The user's phone number
            channel_id: 887, // Channel ID (refer to PayHero docs)
            provider: "m-pesa", // Payment provider
            external_reference: `INV-${newOrder._id}`, // Unique reference for the transaction
            callback_url: "https://97d9-2c0f-fe38-240c-175a-e836-969a-c30b-39bd.ngrok-free.app/", // Your callback URL to handle payment notifications
            description: items.map((item) => `${item.name} x ${item.quantity}`).join(', '), // Item description
        };
        console.log("Making STK Push with Payment Details:", paymentDetails);

        // Make the PayHero STK push request
        const response = await payHero.makeStkPush(paymentDetails); // Await the response from PayHero
        console.log("STK Push Success:", response);

        // Send a successful response back to the frontend
        res.json({ success: true, message: "Payment request sent successfully", data: response });

    } catch (error) {
        console.error("PayHero Error:", error);
        return res.status(500).json({ success: false, message: "Error with PayHero payment", error });
    }
};

const verifyOrder = async(req, res)=>{
    const {orderId, success} = req.body;
    try{
        if(success=="true"){
            await orderModel.findByIdAndUpdate(orderId, {payment:true});
            res.json({success:true, message:"Paid"})
        } else{
            await orderModel.findByIdAndDelete(orderId)
            res.json({success:false, message:"Not Paid"})
        }
    } catch(error){
        console.log(error)
        res.json({success:false, message:"Error"})
    }
}

const userOrders = async (req, res) => {
    try {
        const userId = req.body.userId; // Ensure userId is being passed from the frontend

        if (!userId) {
            return res.status(400).json({ success: false, message: "User ID is required" });
        }

        const orders = await orderModel.find({ userId });

        if (!orders || orders.length === 0) {
            return res.status(404).json({ success: false, message: "No orders found for this user" });
        }

        res.json({ success: true, data: orders });
    } catch (error) {
        console.error("Error fetching user orders:", error);
        res.status(500).json({ success: false, message: "Error fetching orders" });
    }
};

// order control for admin
const listOrders = async(req, res)=>{
    try{
        const orders = await orderModel.find({});
        res.json({success:true, data:orders})
    } catch(error){
        console.log(error)
        res.json({success:false, message:"Error"})
    }
}

const updateStatus = async(req, res)=>{
    try {
        await orderModel.findByIdAndUpdate(req.body.orderId,{status:req.body.status})
        res.json({success:true, message:"Status Updated"})
    } catch (error) {
        console.log(error)
        res.json({success:false, message:"Error"})
    }
}

// const removeOrder = async (req, res) => {
//     try {
//         const { id } = req.body; // Ensure that the order ID is passed in the request body

//         // Validate input
//         if (!id) {
//             return res.status(400).json({ success: false, message: "Order ID is required" });
//         }

//         // Find and delete the order
//         const order = await orderModel.findByIdAndDelete(id);

//         // If the order doesn't exist
//         if (!order) {
//             return res.status(404).json({ success: false, message: "Order not found" });
//         }

//         res.json({ success: true, message: "Order removed successfully" });
//     } catch (error) {
//         console.error("Error removing order:", error);
//         res.status(500).json({ success: false, message: "Error removing order" });
//     }
// };



export { placeOrder, verifyOrder, userOrders, listOrders, updateStatus };