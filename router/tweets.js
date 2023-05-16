import express from 'express';
import * as tweetController from '../controller/tweet.js';
import {body} from 'express-validator';
import {validate} from '../middleware/validator.js';


const router = express.Router();

const validateTweet = [
    body('text')
        .trim()
        .isLength({min:4})
        .withMessage('text는 최소 4자 이상입니다.'),
    validate
]

const app = express();
app.use(express.json());

import { isAuth } from '../middleware/auth.js';

// GET         키         값
// /tweets? username=:username
router.get('/',  isAuth, tweetController.getTweets);

// GET
//   /tweets/:id
router.get('/:id',  isAuth, tweetController.getTweet); 


// text가 4자리 이하인 경우 에러처리해보기 (5/2)
// POST
// id: Date.now().toString()
router.post('/',  isAuth, validateTweet, tweetController.createTweet);


// PUT
// text만 수정
router.put('/:id', isAuth,  validateTweet, tweetController.updateTweet);

// Delete
router.delete('/:id', isAuth, tweetController.deleteTweet);



export default router;
