import express from 'express';
import orderModel from '../models/orderModel.js';

const router = express.Router();

// Handle IPN notifications
router.post('/ipn', async (req, res) => {
    const { orderId, success } = req.body; // Ensure you receive these from Pesapal
    try {
        if (success === "true") {
            await orderModel.findByIdAndUpdate(orderId, { payment: true });
            res.status(200).json({ success: true, message: "Payment successful" });
        } else {
            await orderModel.findByIdAndDelete(orderId);
            res.status(200).json({ success: false, message: "Payment failed" });
        }
    } catch (error) {
        console.error("Error processing IPN:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

export default router;
