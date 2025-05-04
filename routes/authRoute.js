const router = require('express').Router()
const { userRegister, loginUser, forgotPassword, setnewPassword } = require('../controllers/authController')


router.post('/register', userRegister)

router.post('/login', loginUser)

router.post('/forgot-password', forgotPassword)

router.post('/reset-password', setnewPassword)

//router.post('/login', logoutUser)

//router.get('/refresh', handleRefreshToken)

module.exports = router