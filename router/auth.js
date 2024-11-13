import express from 'express'
import * as authController from '../controller/auth.js'
import { body } from 'express-validator'
import { validate } from '../middleware/validator.js'
import { isAuth } from '../middleware/auth.js'

const router = express.Router()

const validateLogin = [
    body('username').trim().isLength({min:4}).withMessage('최소 4자이상 입력').matches(/^[a-zA-Z0-9]*$/).withMessage('특수문자 사용불가'),
    body('password').trim().isLength({min:8}).withMessage('최소 8자이상 입력'),
    validate
]

const validateSignup = [
    ...validateLogin,
    body('name').trim().notEmpty().withMessage('name을 입력'),
    body('email').trim().isEmail().withMessage('이메일 형식 확인'),
    validate
]

router.post('/signup', validateSignup, authController.signup)

router.post('/login', validateLogin, authController.login)

router.get('/me', isAuth, authController.me)

export default router