import userModel from "../models/userModel.js";

// // Add Items to user cart
// const addToCart = async (req, res) => {
//     try {
//         let userData = await userModel.findById(req.body.userId);
//         let cartData = await userData.cartData

//         if(cartData[req.body.itemId]>0){
//             cartData[req.body.itemId] = 1;
//         }else{
//             cartData[req.body.itemId] += 1
//         }
//         await userModel.findByIdAndUpdate(req.body.userId, {cartData});
//         res.json({success:true, message:"Added to Cart"})
//     } catch (error) {
//         console.log(error);
//         res.status(500).json({ success: false, message: "Error" });
//     }
// };

// // Remove Items from user cart
// const removeFromCart = async (req, res) => {
//     try {
//         let userData = await userModel.findById(req.body.userId);
//         let cartData = await userData.cartData

//         if(cartData[req.body.itemId]>0){
//             cartData[req.body.itemId] -= 1;
//         }
//         await userModel.findByIdAndUpdate(req.body.userId, {cartData})
//         res.json({success:true, message:"Removed from cart"})
//     } catch (error) {
//         console.log(error);
//         res.status(500).json({ success: false, message: "Error" });
//     }
// };

// // Fetch user cart
// const getCart = async (req, res) => {
//     try {
//         let userData = await userModel.findById(req.body.userId);
//         let cartData = await userData.cartData
//         res.json({success:true, cartData})
//     } catch (error) {
//         console.log(error);
//         res.status(500).json({ success: false, message: "Error" });
//     }
// };

// Add Items to user cart
const addToCart = async (req, res) => {
    try {
        let userData = await userModel.findById(req.body.userId);
        let cartData = userData.cartData || {};

        // Add or increment item in the cart
        if (!cartData[req.body.itemId]) {
            cartData[req.body.itemId] = 1;
        } else {
            cartData[req.body.itemId] += 1;
        }

        // Update the user's cart in the database
        await userModel.findByIdAndUpdate(req.body.userId, { cartData });

        res.json({ success: true, cartData });
    } catch (error) {
        console.error("Error adding item to cart:", error);
        res.status(500).json({ success: false, message: "Error adding item to cart" });
    }
};

// Remove Items from user cart
const removeFromCart = async (req, res) => {
    try {
        let userData = await userModel.findById(req.body.userId);
        let cartData = userData.cartData || {};

        // Decrement the item count, or remove if count reaches 0
        if (cartData[req.body.itemId]) {
            cartData[req.body.itemId] -= 1;
            if (cartData[req.body.itemId] <= 0) {
                delete cartData[req.body.itemId];  // Remove item if quantity reaches 0
            }
        }

        // Update the user's cart in the database
        await userModel.findByIdAndUpdate(req.body.userId, { cartData });

        res.json({ success: true, cartData });
    } catch (error) {
        console.error("Error removing item from cart:", error);
        res.status(500).json({ success: false, message: "Error removing item from cart" });
    }
};

// Fetch user cart
const getCart = async (req, res) => {
    try {
        let userData = await userModel.findById(req.body.userId);
        let cartData = userData.cartData || {};
        res.json({ success: true, cartData });
    } catch (error) {
        console.error("Error fetching cart data:", error);
        res.status(500).json({ success: false, message: "Error fetching cart data" });
    }
};


export { addToCart, removeFromCart, getCart };
