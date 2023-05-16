/*
    회원가입 -> post로 /signup 페이지를 호출했을 때 들어오도록
    name: 빈 문자 X (notEmpty())
    email: 이메일형식 체크, 모두 소문자로.
    url: URL체크(isURL())

    로그인 -> post로 /login 페이지를 호출했을 때 들어오도록
    username: 공백 X, 빈 문자 X
    password: 공백 X, 최소 4자 이상.
*/ 

import express from 'express';
import * as tweetController from '../controller/tweet.js';
import {body} from 'express-validator';
import {validate} from '../middleware/validator.js';
import * as authController from '../controller/auth.js';


const router = express.Router();

const validateCredential = [
    body('username')
        .trim()
        .isLength({min:4})
        .withMessage('id는 최소 4자 이상 입력좀'),
    body('password')
        .trim()
        .isLength({min:4})
        .withMessage('pw는 최소 4자 이상 입력좀'),
    validate
];

const validateSignup = [
    ...validateCredential,
    body('name').notEmpty().withMessage('이름은 꼭 입력좀'),
    body('email').isEmail().normalizeEmail().withMessage('이메일을 입력좀'),
    body('url').isURL().withMessage('URL 입력좀')
        .optional({nullable: true, checkFalsy:true}), // data가 null이어도 true.
    validate
];

router.post('/signup', validateSignup, authController.signup);

router.post('/login', validateCredential, authController.login);

import { isAuth } from '../middleware/auth.js';

router.get('/me', isAuth, authController.me);

export default router;

