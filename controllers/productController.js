import productModel from "../models/productModel.js"
import fs from "fs"

const addProduct = async (req, res) => {
    let image_filename = `${req.file.filename}`;
    
    // Log the request body for debugging
    console.log("Request Body:", req.body);

    const product = new productModel({
        name: req.body.name,
        description: req.body.description, 
        price: req.body.price,
        category: req.body.category,
        image: image_filename
    });

    try {
        await product.save();
        res.json({ success: true, message: "Product Added" });
    } catch (error) {
        console.log(error);
        res.status(400).json({ success: false, message: error.message }); // Send error message back
    }
}

// all product list

const listProduct = async(req, res) =>{
    try {
        const products = await productModel.find({})
        res.json({success:true, data:products})
    } catch (error) {
        console.log(error)
        res.status(400).json({success:false,message: error.message})
    }
}


// remove products
const removeProduct = async(req, res) =>{
    try {
        const product = await productModel.findById(req.body.id)
        fs.unlink(`upload/${product.image}`, ()=>{})
        
        await productModel.findByIdAndDelete(req.body.id)
        res.json({success:true, message:"Product Removed"})
    } catch (error) {
        console.log(error)
        res.status(400).json({success:false,message: error.message})
    }
}

export {addProduct, listProduct, removeProduct};