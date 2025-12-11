"use strict";

const mongoose = require("mongoose");

const commentSchema = new mongoose.Schema({
    // 1. 댓글 내용
    text: {
        type: String,
        required: true
    },
    // 2. 댓글 작성자
    author: {
        type: String,
        required: true
    },
    // 3. 이 댓글이 달린 게시물의 ID
    postId: {
        type: String,
        required: true
    },
    // 4. 작성일
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model("Comment", commentSchema);