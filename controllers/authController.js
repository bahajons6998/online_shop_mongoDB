const asyncHandler = require('express-async-handler')
const Users = require('../models/userModel')
const CryptoJS = require('crypto-js')
const jwt = require('jsonwebtoken')
const { Cart } = require("../models/cartModel");
const nodemailer = require('nodemailer');

//To Register a User
userRegister = asyncHandler(async (req, res) => {
    const { username, email, password, isAdmin } = req.body
    console.log('ishlayapti: ', req.body);

    if (!username || !email || !password) {
        throw new Error('All fields are mandatory')
    }

    const usernameAvailable = await Users.findOne({ username })
    if (usernameAvailable) {
        throw new Error('UserName Taken')
    }
    const emailAvailable = await Users.findOne({ email })
    if (emailAvailable) {
        throw new Error('Email Taken')
    }
    else {
        const hashedPassword = CryptoJS.AES.encrypt(password, process.env.PASSWORD_KEY).toString()
        const user = await Users.create({
            username, email, password: hashedPassword, isAdmin
        })
        if (user) {
            const { password, ...others } = user._doc
            res.status(201).json(others)
        }
        else {
            res.status(400)
            throw new Error('Data not valid')
        }
    }
})

//To Login using existing Users
loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body

    console.log('ishlayapti: ', req.body);
    if (!email || !password) {
        res.status(400).json({ message: 'All fields are mandatory' })
    }
    const user = await Users.findOne({ email })

    if (!user) {
        res.status(400).json({ message: "No such User" })
    }
    const decryptedPassword = CryptoJS.AES.decrypt(user.password, process.env.PASSWORD_KEY).toString(CryptoJS.enc.Utf8)
    if (decryptedPassword !== password) {
        res.status(400)
        throw new Error('Invalid Password')
    }
    const accessToken = jwt.sign({
        _id: user._id,
        isAdmin: user.isAdmin,
    }, process.env.JWT_KEY, { expiresIn: '1d' })

    let cart = await Cart.findOne({ userId: user._id });
    if (!cart) {
        await Cart.create({
            userId: user._id,
            products: [],
        })
    }

    res.status(200).json({
        _id: user._id,
        username: user.username,
        email: user.email,
        accessToken,
        isAdmin: user.isAdmin
    })
})

forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body
    console.log('ishlayapti: ', req.body);

    if (!email) {
        res.status(400).json({ message: 'All fields are mandatory' })
    }
    const user = await Users.findOne({ email })

    if (!user) {
        res.status(400).json({ message: "No such User" })
    }

    // Generate password reset token
    const resetToken = jwt.sign(
        { userId: user._id },
        process.env.JWT_KEY,
        { expiresIn: '1h' }
    )

    // Create password reset link
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}&email=${email}`

    // Send reset password email

    // Create email transporter
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    });

    // Configure email options
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset Link',
        html: `
            <h1>Password Reset Request</h1>
            <p>Click the link below to reset your password:</p>
            <a href="${resetLink}">Reset Password</a>
            <p>This link will expire in 1 hour.</p>
        `
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    // TODO: Implement email sending functionality
    // For now, just return the reset link in response
    res.status(200).json({
        message: "Password reset link generated",
        resetLink
    })
})

setnewPassword = asyncHandler(async (req, res) => {
    const { token, email, password } = req.body
    console.log('ishlayapti: ', req.body);

    if (!token || !email || !password) {
        res.status(400).json({ message: 'All fields are mandatory' })
    }

    // Verify reset token
    try {
        const decoded = jwt.verify(token, process.env.JWT_KEY)
        const user = await Users.findOne({ email })

        if (!user || user._id.toString() !== decoded.userId) {
            return res.status(400).json({ message: "Invalid or expired reset token" })
        }

        const hashedPassword = CryptoJS.AES.encrypt(password, process.env.PASSWORD_KEY).toString()
        const updatedUser = await Users.findByIdAndUpdate(
            user._id,
            { password: hashedPassword },
            { new: true }
        )

        res.status(200).json({
            message: "Password updated successfully",
            user: {
                _id: updatedUser._id,
                email: updatedUser.email,
                username: updatedUser.username
            }
        })

    } catch (error) {
        res.status(400).json({ message: "Invalid or expired reset token" })
    }
})



module.exports = { userRegister, loginUser, forgotPassword, setnewPassword };