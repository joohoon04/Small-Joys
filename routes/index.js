"use strict";

const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { start } = require("repl");

// 모델 불러오기 (Mongoose에 스키마를 등록하는 역할만 합니다.)
require("../models/User");
const { Challenge, initialChallenges } = require("../models/Challenge"); 
require("../models/Comment");
require("../models/Post");

// Mongoose 캐시에서 모델을 가져와 변수에 할당합니다.
const User = mongoose.model('User');
const Comment = mongoose.model('Comment');
const Post = mongoose.model('Post');

// Multer 저장소 설정
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// ⭐ [관리자 기능] 관리자 전용 미들웨어 (Admin Check Middleware)
const requireAdmin = (req, res, next) => {
    // 1. 로그인 여부 확인
    if (!req.session.isLoggedIn) {
        req.session.errorMessage = "로그인이 필요합니다.";
        return res.redirect("/login");
    }
    // 2. 관리자 권한 확인
    if (!req.session.user || !req.session.user.isAdmin) {
        req.session.errorMessage = "관리자 권한이 필요합니다.";
        return res.redirect("/home");
    }
    next();
};

// --- 1. 인증(Auth) 관련 라우트 ---
router.get("/", (req, res) => {
    const errorMessage = req.session.errorMessage;
    delete req.session.errorMessage;
    res.render("index/login", { errorMessage: errorMessage });
});
router.get("/login", (req, res) => {
    const errorMessage = req.session.errorMessage;
    delete req.session.errorMessage;
    res.render("index/login", { errorMessage: errorMessage });
});

// ⭐ [수정] 로그인 라우트: isAdmin 정보를 세션에 저장 및 관리자 리다이렉트 처리
router.post("/login", async (req, res) => {
    try {
        const { id, password } = req.body;

        const user = await User.findOne({ id: id }); 

        if (!user) {
            req.session.errorMessage = "아이디 또는 비밀번호가 올바르지 않습니다.";
            return res.redirect("/login");
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            req.session.isLoggedIn = true;
            // ⭐ 세션에 isAdmin 필드 추가 (User 모델에 있다고 가정)
            req.session.user = { 
                _id: user._id.toString(), // ObjectId를 문자열로 변환하여 세션에 저장
                id: user.id, 
                name: user.name,
                challenges: user.challenges || [],
                isAdmin: user.isAdmin || false 
            };
            
            // 관리자라면 /admin으로 리다이렉트
            if (user.isAdmin) {
                return res.redirect("/admin");
            }
            return res.redirect("/home");
        } else {
            req.session.errorMessage = "아이디 또는 비밀번호가 올바르지 않습니다.";
            return res.redirect("/login");
        }
    } catch (error) {
        console.error("로그인 처리 오류:", error);
        req.session.errorMessage = "로그인 처리 중 서버 오류가 발생했습니다.";
        res.redirect("/login");
    }
});
router.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.redirect("/home");
        res.redirect("/login");
    });
});

router.get("/register", (req, res) => {
    const errorMessage = req.session.errorMessage;
    delete req.session.errorMessage;
    res.render("index/register", { errorMessage: errorMessage }); 
});

// ⭐ [수정] 회원가입 라우트: 관리자 코드를 통해 관리자 계정 생성
router.post("/register", async (req, res) => {
    try {
        const { id, name, email, phone, password, confirm_password, adminCode } = req.body; 
        const ADMIN_SECRET_CODE = "ADMIN1234!"; // 임시 관리자 비밀 코드

        if (!id || !name || !password || !confirm_password) {
            req.session.errorMessage = "아이디, 이름, 비밀번호는 필수 입력 항목입니다.";
            return res.redirect("/register");
        }
        
        if (password !== confirm_password) {
            req.session.errorMessage = "비밀번호와 비밀번호 확인이 일치하지 않습니다.";
            return res.redirect("/register");
        }

        const existingUserById = await User.findOne({ id: id });
        if (existingUserById) {
            req.session.errorMessage = "이미 사용 중인 아이디입니다. 다른 아이디를 사용해주세요.";
            return res.redirect("/register");
        }
        
        // 이메일 중복 확인
        if (email) { 
            const existingUserByEmail = await User.findOne({ email: email });
            if (existingUserByEmail) {
                req.session.errorMessage = "이미 사용 중인 이메일입니다.";
                return res.redirect("/register");
            }
        }
        
        // 전화번호 중복 확인
        if (phone) { 
            const existingUserByPhone = await User.findOne({ phone: phone });
            if (existingUserByPhone) {
                req.session.errorMessage = "이미 사용 중인 전화번호입니다.";
                return res.redirect("/register");
            }
        }
        
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // ⭐ 관리자 여부 확인 및 설정
        let isAdmin = false;
        if (adminCode && adminCode === ADMIN_SECRET_CODE) {
            isAdmin = true;
        }

        const user = new User({
            id, 
            name,
            email,
            phone,
            password: hashedPassword,
            username: id, 
            isAdmin: isAdmin 
        });

        await user.save();
        
        if (isAdmin) {
             req.session.errorMessage = "관리자 계정으로 회원가입이 완료되었습니다. 로그인 해주세요.";
        } else {
             req.session.errorMessage = "회원가입이 완료되었습니다. 로그인 해주세요.";
        }
        res.redirect("/login");

    } catch (error) {
        let errorMessage = "회원가입 처리 중 알 수 없는 서버 오류가 발생했습니다.";
        
        if (error.code === 11000) {
            errorMessage = "이미 사용 중인 정보(아이디 또는 이메일, 전화번호)가 있습니다. 다른 정보를 사용해주세요.";
        }
        
        req.session.errorMessage = errorMessage;
        res.redirect("/register");
    }
});  

// --- 2. 나의 다이어리 / 댓글 라우트 ---

router.get("/home", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const myPosts = await Post.find({ authorId: req.session.user.id })
                                 .sort({ createdAt: -1 }); 
        res.render("index/home", {
            user: req.session.user,
            posts: myPosts 
        });
    } catch (error) {
        console.error("나의 다이어리 로딩 중 오류:", error);
        res.redirect("/login");
    }
});
router.get("/my-diary", (req, res) => res.redirect("/home"));

// POST /post/:id/comment (댓글 저장)
router.post("/post/:id/comment", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login"); 
    try {
        const newComment = new Comment({
            text: req.body.commentText,
            author: req.session.user.id,
            postId: req.params.id 
        });
        await newComment.save();
        res.redirect(req.headers.referer || "/home");
    } catch (error) {
        res.redirect("/home");
    }
});

// ⭐ [수정] POST /comment/delete/:commentId (댓글 삭제): 관리자 권한 추가
router.post("/comment/delete/:commentId", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    
    // ⭐ [수정] 관리자 권한 변수 설정
    const isAdmin = req.session.user && req.session.user.isAdmin;

    try {
        const comment = await Comment.findById(req.params.commentId);

        if (!comment) {
            req.session.errorMessage = "존재하지 않는 댓글입니다.";
            return res.redirect(req.headers.referer || "/home");
        }

        // ⭐ [수정] 삭제 조건: 작성자이거나 관리자(isAdmin: true)일 경우 삭제 가능
        if (comment.author === req.session.user.id || isAdmin) {
            await Comment.findByIdAndDelete(req.params.commentId);
            req.session.errorMessage = "댓글이 삭제되었습니다.";
        } else {
            // 권한 없음
            req.session.errorMessage = "삭제 권한이 없습니다.";
        }
        
        res.redirect(req.headers.referer || "/home");
    } catch (error) {
        console.error("댓글 삭제 오류:", error);
        req.session.errorMessage = "댓글 삭제 처리 중 오류가 발생했습니다.";
        res.redirect(req.headers.referer || "/home");
    }
});

// --- 3. 공유 페이지 (게시물 목록) 라우트 ---

router.get("/shared", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const searchTerm = req.query.search || ""; 
        const query = { isPublic: true };
        if (searchTerm) {
            query.$or = [
                { title: { $regex: searchTerm, $options: "i" } },
                { content: { $regex: searchTerm, $options: "i" } }
            ];
        }
        const posts = await Post.find(query).sort({ createdAt: -1 });
        const allComments = await Comment.find().select('postId');
        const commentCounts = allComments.reduce((acc, comment) => {
            const postId = comment.postId.toString();
            acc[postId] = (acc[postId] || 0) + 1;
            return acc;
        }, {});
        const postsWithCounts = posts.map(post => {
            const postObj = post.toObject();
            postObj.commentCount = commentCounts[post._id.toString()] || 0;
            return postObj;
        });
        res.render("index/shared", {
            user: req.session.user,
            posts: postsWithCounts,
            searchTerm: searchTerm
        });
    } catch (error) {
        console.error("공유페이지 로딩 중 오류:", error);
        res.send("페이지를 불러올 수 없습니다.");
    }
});

// --- 4. 새 글 쓰기 (Post) 라우트 ---

router.get("/post/new", async (req, res) => {
   if (!req.session.isLoggedIn) return res.redirect("/login");
    
    const userLoginId = req.session.user.id;
    let joinedChallenges = []; 

    try {
        const userWithChallenges = await User.findOne({ id: userLoginId })
            .populate({
                path: 'joinedChallenges.challengeId',
                model: 'Challenge'
            });

        if (userWithChallenges && userWithChallenges.joinedChallenges) {
            
            joinedChallenges = userWithChallenges.joinedChallenges
                .filter(item => item.challengeId !== null) 
                .map(item => item.challengeId);
        }
        res.render("index/new-post", { 
            user: req.session.user,
            challenges: joinedChallenges, // 유효한 Challenge 문서 배열
        });

    } catch (error) {
        console.error("새 일기 쓰기 페이지 로드 중 오류:", error);
        res.redirect("/home");
    }
});

router.post("/post/new", upload.single("postImage"), async (req, res) => {
    const user = req.session.user;
    if (!user) return res.redirect("/login");

    const { title, content, isPublic, challengeId } = req.body; 

    try {
        const newPost = new Post({
            title: title,
            content: content,
            imageUrl: req.file ? `/uploads/${req.file.filename}` : undefined,
            authorId: user.id, 
            isPublic: !!isPublic,
            challengeId: challengeId || null 
        });

        await newPost.save();
        
        // 챌린지 성공 여부 확인 로직
        if (challengeId) {
            const challenge = await Challenge.findById(challengeId);
            if (challenge) {
                const requiredCount = challenge.duration;

                const currentPostsCount = await Post.countDocuments({ 
                    authorId: user.id, 
                    challengeId: challengeId 
                });

                if (currentPostsCount >= requiredCount) {
                    await User.updateOne(
                        { id: user.id, 'joinedChallenges.challengeId': challengeId },
                        { $set: { 'joinedChallenges.$.status': 'SUCCESS' } } 
                    );
                    console.log(`[Challenge Success] User ${user.id} completed challenge ${challengeId}`);
                }
            }
        }
        req.session.errorMessage = "일기가 성공적으로 저장되었습니다.";
        res.redirect("/home");

    } catch (error) {
        console.error("Post save error:", error);
        req.session.errorMessage = "일기 저장 중 오류가 발생했습니다.";
        res.redirect("/post/new");
    }
});

// --- 5. 글 상세 / 수정 / 삭제 라우트 ---
router.get("/post/detail/:id", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    
    const postId = req.params.id; 
    if (!mongoose.Types.ObjectId.isValid(postId)) {
        console.error(`Invalid Post ID attempted: ${postId}`);
        return res.status(404).send("유효하지 않은 게시물 식별자입니다."); 
    }
    
    try {
        const post = await Post.findById(postId);
        
        if (!post) {
            return res.status(404).send("게시물을 찾을 수 없습니다.");
        }
        
        const comments = await Comment.find({ postId: postId.toString() });
        
        res.render("index/main", {
            user: req.session.user,
            post: post,
            comments: comments
        });
    } catch (error) {
        console.error("상세페이지 로딩 중 오류:", error);
        res.redirect("/home");
    }
});

router.get("/post/edit/:id", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).send("게시물을 찾을 수 없습니다.");

        if (post.authorId !== req.session.user.id) {
            console.log("수정 권한 없음. 작성자가 다릅니다.");
            return res.redirect("/home");
        }

        res.render("index/edit-post", { 
            user: req.session.user,
            post: post
        });
    } catch (error) {
        console.error("수정 페이지 로딩 중 오류:", error);
        res.redirect("/home");
    }
});

router.post("/post/edit/:id", upload.single('postImage'), async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const postId = req.params.id;
        const post = await Post.findById(postId);
        if (!post) return res.status(40.4).send("게시물을 찾을 수 없습니다.");

        if (post.authorId !== req.session.user.id) {
            console.log("수정 권한 없음. 작성자가 다릅니다.");
            return res.redirect("/home");
        }
        
        const { title, content } = req.body;
        const isPublic = req.body.isPublic === 'true';
        let updateData = { title, content, isPublic };

        if (req.file) {
            updateData.imageUrl = '/uploads/' + req.file.filename;
        }
        
        await Post.findByIdAndUpdate(postId, updateData);

        console.log("게시물 수정 완료:", postId);
        res.redirect(`/post/detail/${postId}`); 

    } catch (error) {
        console.error("게시물 수정 중 오류:", error);
        res.redirect("/home");
    }
});

// ⭐ [수정] POST /post/delete/:id (게시물 삭제): 관리자 권한 추가
router.post("/post/delete/:id", async (req, res) => {
    const postId = req.params.id;
    const user = req.session.user;

    if (!user) {
        req.session.errorMessage = "로그인이 필요합니다.";
        return res.redirect("/login");
    }

    // ⭐ [추가] 관리자 권한 변수 설정
    const isAdmin = user.isAdmin;

    try {
        // 1. 해당 ID의 게시물을 찾습니다.
        const post = await Post.findById(postId);

        if (!post) {
            req.session.errorMessage = "존재하지 않는 일기입니다.";
            return res.redirect("/home");
        }

        // ⭐ [수정] 삭제 조건: 작성자 ID와 세션 ID가 일치하거나 (일반 사용자), isAdmin이 true인 경우 (관리자)
        if (post.authorId === user.id || isAdmin) {
            
            // 2. 일기 및 관련 댓글 삭제 실행
            await Post.deleteOne({ _id: postId });
            await Comment.deleteMany({ postId: postId }); // 해당 게시물의 댓글도 모두 삭제
            
            // 관리자 삭제 시 메시지 다르게 표시
            if (isAdmin && post.authorId !== user.id) {
                req.session.errorMessage = `관리자 권한으로 사용자 (${post.authorId})의 일기가 삭제되었습니다.`;
            } else {
                req.session.errorMessage = "일기가 성공적으로 삭제되었습니다.";
            }
            
            return res.redirect("/home");
            
        } else {
            // 권한 없음
            console.log(`사용자 ${user.id}는 게시물 ${postId}의 작성자가 아닙니다.`);
            req.session.errorMessage = "삭제 권한이 없습니다.";
            return res.redirect("/home");
        }
        
    } catch (error) {
        console.error("일기 삭제 중 오류 발생:", error);
        req.session.errorMessage = "일기 삭제 처리 중 오류가 발생했습니다.";
        res.redirect("/home");
    }
});

// --- 6. 마이페이지 라우트 ---
router.get("/mypage", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const dbUser = await User.findById(req.session.user._id);
        if (!dbUser) return res.redirect("/logout");

        const errorMessage = req.session.errorMessage;
        delete req.session.errorMessage;

        res.render("index/mypage", { user: dbUser, errorMessage: errorMessage });
    } catch (error) {
        res.redirect("/home");
    }
});
router.post("/mypage", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const userId = req.session.user._id;
        const { name, email, phone, password, confirm_password } = req.body;
        const updateData = { name, email, phone };
        
        if (password && password.length > 0) {
            if (password !== confirm_password) {
                req.session.errorMessage = "비밀번호와 비밀번호 확인이 일치하지 않습니다.";
                return res.redirect("/mypage");
            }
            
            // 비밀번호 암호화 후 저장
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            updateData.password = hashedPassword;
        }
        
        const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true });
        
        // 세션 정보 업데이트
        req.session.user.name = updatedUser.name;
        
        res.redirect("/mypage");
    } catch (error) {
        if (error.code === 11000) {
             console.error("마이페이지 업데이트 중 중복 오류:", error);
             req.session.errorMessage = "이미 사용 중인 이메일 또는 전화번호입니다. 다른 정보를 사용해주세요.";
        } else {
             console.error("마이페이지 업데이트 중 오류:", error);
             req.session.errorMessage = "정보 수정 중 서버 오류가 발생했습니다.";
        }
        res.redirect("/mypage");
    }
});
router.post("/withdraw", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const userId = req.session.user._id;
        const userDbId = req.session.user.id;
        await Comment.deleteMany({ author: userDbId });
        await Post.deleteMany({ authorId: userDbId });
        await User.findByIdAndDelete(userId);
        req.session.destroy((err) => {
            if (err) return res.redirect("/home");
            res.redirect("/login");
        });
    } catch (error) {
        res.redirect("/home");
    }
});
 
router.get("/main", (req, res) => {
    res.redirect("/shared");
});

// --- 7. 행복 찾기(Happy Find) 및 챌린지 관련 라우트 ---

// GET /happy-find: 행복 찾기 허브 (챌린지 목록, 랜덤 발견 버튼)
router.get("/happy-find", async (req, res) => {
    try {
        const user = req.session.user; 
        if (!user) return res.redirect("/login");

        const allChallenges = await Challenge.find({ isActive: true }).sort({ startDate: -1 });
        
        const fullUser = await User.findOne({ id: user.id })
            .populate('joinedChallenges.challengeId'); 
        
        const userPosts = await Post.find({ authorId: user.id, challengeId: { $ne: null } });

        const challengesWithStatus = allChallenges.map(c => {
            const userChallenge = fullUser.joinedChallenges.find(
                jc => jc.challengeId && jc.challengeId._id.equals(c._id) 
            );

            let status = '미참여';
            let currentPostsCount = 0;

            if (userChallenge) {
                status = '참여 중'; 

                currentPostsCount = userPosts.filter(
                    p => p.challengeId && p.challengeId.equals(c._id)
                ).length;
                
                if (currentPostsCount >= c.duration) {
                    status = '챌린지 성공';
                } 
            }

            return {
                ...c.toObject(),
                currentPostsCount: currentPostsCount,
                status: status
            };
        });

        const errorMessage = req.session.errorMessage;
        delete req.session.errorMessage;

        res.render("index/happy-find", {
            challenges: challengesWithStatus,
            user: user,
            errorMessage: errorMessage
        });
    } catch (error) {
        console.error("Error fetching challenges:", error);
        req.session.errorMessage = "챌린지 목록을 불러오는 중 오류가 발생했습니다.";
        res.redirect("/home"); 
    }
});

// POST /challenges/:id/join: 챌린지 참여
router.post("/challenges/:challengeId/join", async (req, res) => {
    const { challengeId } = req.params;
    const user = req.session.user;

    if (!user) return res.redirect("/login");
    
    try {
        const updateResult = await User.updateOne(
            { id: user.id, 'joinedChallenges.challengeId': { $ne: challengeId } }, 
            { $push: { 
                joinedChallenges: { 
                    challengeId: challengeId,
                    status: '진행중' 
                } 
            }}
        );
        if (updateResult.modifiedCount === 0 && updateResult.matchedCount > 0) {
            req.session.errorMessage = "이미 챌린지에 참여 중입니다.";
        } else {
            req.session.errorMessage = "챌린지에 참여했습니다! 🎉";
        }
    } catch (error) {
        console.error("Challenge join error:", error);
        req.session.errorMessage = "챌린지 참여 중 오류가 발생했습니다.";
    }
    res.redirect("/happy-find");
});

// 챌린지 참여 취소 라우트
router.post("/challenges/:challengeId/leave", async (req, res) => {
    const user = req.session.user;
    const challengeId = req.params.challengeId;

    if (!user) {
        req.session.errorMessage = "로그인이 필요합니다.";
        return res.redirect("/login");
    }

    try {
        await User.updateOne(
            { id: user.id },
            { 
                $pull: { 
                    joinedChallenges: { 
                        challengeId: challengeId 
                    } 
                } 
            }
        );

        req.session.errorMessage = "챌린지 참여가 성공적으로 취소되었습니다.";
        res.redirect("/happy-find");
    } catch (error) {
        console.error("Leave challenge error:", error);
        req.session.errorMessage = "챌린지 참여 취소 중 오류가 발생했습니다.";
        res.redirect("/happy-find");
    }
});

// GET /random: 무작위 행복 기록 조회
router.get("/random", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const [randomPost] = await Post.aggregate([
            { $match: { isPublic: true } },
            { $sample: { size: 1 } },
            {
                $lookup: {
                    from: 'users',      
                    localField: 'authorId', 
                    foreignField: 'id', 
                    as: 'authorInfo'
                }
            },
            {
                $project: {
                    _id: 1,
                    title: 1,
                    content: 1,
                    imageUrl: 1,
                    createdAt: 1,
                    authorId: {
                        $cond: {
                            if: { $eq: [{ $arrayElemAt: ["$authorInfo.isRandomExposed", 0] }, false] }, 
                            then: "익명의 행복 전도사", 
                            else: "$authorId" 
                        }
                    }
                }
            }
        ]);

        if (randomPost) {
            res.render("index/random-view", { 
                post: randomPost,
                user: req.session.user
            });
        } else {
            req.session.errorMessage = "현재 공유된 행복 기록이 없습니다.";
            res.redirect("/happy-find");
        }
    } catch (error) {
        console.error("랜덤 발견 오류:", error);
        res.redirect("/happy-find");
    }
});

// ⭐ [관리자 기능] 관리자 모드 라우트 ---
// GET /admin: 관리자 대시보드
router.get("/admin", requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({});
        const totalPosts = await Post.countDocuments({});
        // 최근 50명의 사용자 정보만 가져와서 표시
        const users = await User.find().sort({ createdAt: -1 }).limit(50); 

        const errorMessage = req.session.errorMessage;
        delete req.session.errorMessage;

        res.render("index/admin/dashboard", {
            user: req.session.user,
            totalUsers,
            totalPosts,
            users,
            errorMessage
        });
    } catch (error) {
        console.error("관리자 대시보드 로딩 오류:", error);
        req.session.errorMessage = "데이터를 불러오는 중 오류가 발생했습니다.";
        res.redirect("/home");
    }
});

// POST /admin/user/:id/delete: 사용자 강제 탈퇴
router.post("/admin/user/:id/delete", requireAdmin, async (req, res) => {
    const userId = req.params.id; // 삭제할 사용자(_id)
    
    try {
        const userToDelete = await User.findById(userId);

        if (!userToDelete) {
            req.session.errorMessage = "존재하지 않는 사용자입니다.";
            return res.redirect("/admin");
        }
        
        // 관리자 본인 계정은 삭제 방지
        if (userToDelete._id.toString() === req.session.user._id) {
            req.session.errorMessage = "본인 관리자 계정은 강제 탈퇴할 수 없습니다.";
            return res.redirect("/admin");
        }

        const userDbId = userToDelete.id; // Post/Comment 삭제를 위한 사용자 로그인 ID
        
        // 1. 해당 사용자의 댓글, 게시물 모두 삭제
        await Comment.deleteMany({ author: userDbId });
        await Post.deleteMany({ authorId: userDbId });
        
        // 2. 사용자 계정 삭제
        await User.findByIdAndDelete(userId);

        req.session.errorMessage = `사용자 (${userDbId})가 강제 탈퇴되었습니다.`;
        res.redirect("/admin");

    } catch (error) {
        console.error("관리자 사용자 삭제 오류:", error);
        req.session.errorMessage = "사용자 강제 탈퇴 중 오류가 발생했습니다.";
        res.redirect("/admin");
    }
});

// POST /admin/user/:id/toggle-admin: 관리자 권한 부여/회수
router.post("/admin/user/:id/toggle-admin", requireAdmin, async (req, res) => {
    const userId = req.params.id;
    
    try {
        const userToUpdate = await User.findById(userId);

        if (!userToUpdate) {
            req.session.errorMessage = "존재하지 않는 사용자입니다.";
            return res.redirect("/admin");
        }
        
        // 권한 토글 (현재 상태의 반대로 설정)
        const newAdminStatus = !userToUpdate.isAdmin;
        
        // 업데이트
        await User.findByIdAndUpdate(userId, { isAdmin: newAdminStatus });
        
        const statusText = newAdminStatus ? "관리자 권한이 부여" : "관리자 권한이 회수";
        req.session.errorMessage = `사용자 (${userToUpdate.id})에게 ${statusText}되었습니다.`;
        res.redirect("/admin");

    } catch (error) {
        console.error("관리자 권한 토글 오류:", error);
        req.session.errorMessage = "관리자 권한 변경 중 오류가 발생했습니다.";
        res.redirect("/admin");
    }
});
// --- 관리자 모드 라우트 끝 ---

module.exports = router;