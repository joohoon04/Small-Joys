// index.js (파일 상단: Line 1 ~ Line 18까지)

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

// 2. Mongoose 캐시에서 모델을 가져와 변수에 할당합니다.
const User = mongoose.model('User');
// const Challenge = mongoose.model('Challenge'); 
const Comment = mongoose.model('Comment');
const Post = mongoose.model('Post');

// Multer 저장소 설정
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });
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
router.post("/login", async (req, res) => {
    try {
        const { id, password } = req.body;

        // 1. ID로 사용자 찾기
        const user = await User.findOne({ id: id }); 

        if (!user) {
            req.session.errorMessage = "아이디 또는 비밀번호가 올바르지 않습니다.";
            return res.redirect("/login");
        }

        // 2. 비밀번호 비교 (bcrypt.compare 사용)
        // 입력된 일반 비밀번호와 DB에 저장된 해시 비밀번호를 비교합니다.
        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            req.session.isLoggedIn = true;
            // 세션에 사용자 정보 저장
            req.session.user = { 
                _id: user._id, 
                id: user.id, 
                name: user.name,
                challenges: user.challenges || []
                // 필요하다면 isRandomExposed 등 다른 필드도 추가
            };
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
// routes/index.js
router.get("/register", (req, res) => {
    const errorMessage = req.session.errorMessage;
    delete req.session.errorMessage;
    // 뷰 경로를 'index/register'로 변경하여 'views/index/register.ejs'를 찾도록 합니다.
    res.render("index/register", { errorMessage: errorMessage }); 
});
// index.js (router.post("/register") 부분)
// index.js (router.post("/register") 부분)
router.post("/register", async (req, res) => {
    try {
        // req.body에서 필요한 필드를 모두 추출합니다.
        const { id, name, email, phone, password, confirm_password } = req.body; 

        // 1. 필수 필드 유효성 검사 추가 (null 또는 빈 문자열 방지)
        if (!id || !name || !password || !confirm_password) {
            req.session.errorMessage = "아이디, 이름, 비밀번호는 필수 입력 항목입니다.";
            return res.redirect("/register");
        }
        
        // 2. 비밀번호 일치 확인 (필수)
        if (password !== confirm_password) {
            req.session.errorMessage = "비밀번호와 비밀번호 확인이 일치하지 않습니다.";
            return res.redirect("/register");
        }

        // 3. 아이디 중복 확인 추가 (DB에서 한번 더 확인)
        const existingUserById = await User.findOne({ id: id });
        if (existingUserById) {
            req.session.errorMessage = "이미 사용 중인 아이디입니다. 다른 아이디를 사용해주세요.";
            return res.redirect("/register");
        }
        
        // 3-1. 이메일 중복 확인 (입력된 경우에만 확인)
        if (email) { 
            const existingUserByEmail = await User.findOne({ email: email });
            if (existingUserByEmail) {
                req.session.errorMessage = "이미 사용 중인 이메일입니다. 다른 이메일을 입력하거나 비워두세요.";
                return res.redirect("/register");
            }
        }
        
        // [⭐️ 확인 및 유지] 3-2. 전화번호 중복 확인 (입력된 경우에만 확인)
        if (phone) { 
            const existingUserByPhone = await User.findOne({ phone: phone });
            if (existingUserByPhone) {
                req.session.errorMessage = "이미 사용 중인 전화번호입니다. 다른 전화번호를 입력하거나 비워두세요.";
                return res.redirect("/register");
            }
        }
        // 4. 비밀번호 암호화
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // 5. 새 사용자 생성 및 저장
        const user = new User({
            id, 
            name,
            email,
            phone,
            password: hashedPassword,
            // 문제의 필드: 'username' 필드가 'id'와 동일한 값을 갖도록 명시
            username: id, 
        });

        await user.save();
        
        req.session.errorMessage = "회원가입이 완료되었습니다. 로그인 해주세요.";
        res.redirect("/login");

    } catch (error) {
        // 1. catch 블록 최상단에서 errorMessage 변수를 선언하고 기본값을 할당합니다.
        let errorMessage = "회원가입 처리 중 알 수 없는 서버 오류가 발생했습니다.";
        
        if (error.name === 'ValidationError') {
            // 이메일이나 전화번호 같은 필수 아닌 항목의 유효성 검사 실패 시
            errorMessage = "필수 입력 항목을 모두 채워주세요. (아이디, 이름, 비밀번호)";
        } 
        
        // [유지] E11000 Duplicate Key Error 처리
        else if (error.code === 11000) {
            // 이 오류는 id, email, phone, 또는 username 등 고유 인덱스가 설정된 필드가 중복되었을 때 발생합니다.
            // DB에 남은 username: null 문서가 원인일 수 있습니다.
            errorMessage = "이미 사용 중인 정보(아이디 또는 이메일, 전화번호)가 있습니다. 다른 정보를 사용해주세요.";
        }
        
        // 2. 정의된 변수를 사용하여 세션에 오류 메시지를 저장합니다.
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

// POST /comment/delete/:commentId (댓글 삭제)
router.post("/comment/delete/:commentId", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");
    try {
        const comment = await Comment.findById(req.params.commentId);
        if (comment && comment.author === req.session.user.id) {
            await Comment.findByIdAndDelete(req.params.commentId);
        }
        res.redirect(req.headers.referer || "/home");
    } catch (error) {
        res.redirect("/home");
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

/// index.js 라우터 파일 내 POST /post/new
router.post("/post/new", upload.single("postImage"), async (req, res) => {
    const user = req.session.user;
    if (!user) return res.redirect("/login");

    // req.body에서 challengeId를 추가로 구조 분해 할당
    const { title, content, isPublic, challengeId } = req.body; 

    try {
        const newPost = new Post({
            title: title,
            content: content,
            // req.file 사용 시
            imageUrl: req.file ? `/uploads/${req.file.filename}` : undefined,
            authorId: user.id, 
            isPublic: !!isPublic,
            
            // ⭐ 이 부분이 추가되어야 합니다.
            // new-post.ejs에서 챌린지 선택 시 넘어온 challengeId를 저장합니다.
            // 선택하지 않았다면 null이 저장됩니다.
            challengeId: challengeId || null 
        });

        await newPost.save();
        // 챌린지 성공 여부 확인 로직
        if (challengeId) {
            const challenge = await Challenge.findById(challengeId);
            if (challenge) {
                const requiredCount = challenge.duration;

                // 해당 챌린지로 작성된 총 일기 개수 카운트
                const currentPostsCount = await Post.countDocuments({ 
                    authorId: user.id, 
                    challengeId: challengeId 
                });

                // 성공 조건을 만족했고, 현재 DB 상태가 'SUCCESS'가 아니라면 업데이트
                if (currentPostsCount >= requiredCount) {
                    await User.updateOne(
                        { id: user.id, 'joinedChallenges.challengeId': challengeId },
                        { $set: { 'joinedChallenges.$.status': 'SUCCESS' } } // DB에 성공 상태 명시
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
        // 유효하지 않은 요청은 게시물을 찾을 수 없다는 응답을 보냅니다.
        return res.status(404).send("유효하지 않은 게시물 식별자입니다."); 
    }
    
    try {
        // 유효성이 검사된 postId로 Post 찾기
        const post = await Post.findById(postId);
        
        if (!post) {
            // ID 형식은 맞지만 해당 ID의 게시물이 없는 경우
            return res.status(404).send("게시물을 찾을 수 없습니다.");
        }
        
        const comments = await Comment.find({ postId: postId.toString() });
        
        res.render("index/main", {
            user: req.session.user,
            post: post,
            comments: comments
        });
    } catch (error) {
        // 다른 종류의 서버 오류 발생 시 (네트워크, DB 연결 등)
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
        if (!post) return res.status(4.04).send("게시물을 찾을 수 없습니다.");

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

// POST /post/delete/:id (게시물 삭제)
router.post("/post/delete/:id", async (req, res) => {
    const postId = req.params.id;
    const userId = req.session.user ? req.session.user.id : null;

    if (!userId) {
        req.session.errorMessage = "로그인이 필요합니다.";
        return res.redirect("/login");
    }

    try {
        // 1. 해당 ID의 게시물을 찾습니다. (작성자가 맞는지 확인하기 위함)
        const post = await Post.findById(postId);

        if (!post) {
            req.session.errorMessage = "존재하지 않는 일기입니다.";
            return res.redirect("/home");
        }

        // 2. 작성자 ID와 세션 ID가 일치하는지 확인
        if (post.authorId !== userId) {
            req.session.errorMessage = "삭제 권한이 없습니다.";
            return res.redirect("/home");
        }

        // 3. 일기 삭제 실행
        await Post.deleteOne({ _id: postId });

        req.session.errorMessage = "일기가 성공적으로 삭제되었습니다.";
        res.redirect("/home");
        
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
        res.render("index/mypage", { user: dbUser });
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
            if (password !== confirm_password) return res.redirect("/mypage");
            
            // 비밀번호 암호화 후 저장
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            updateData.password = hashedPassword;
        }
        
        // 업데이트 전에 중복 체크를 한 번 더 수행하는 것이 좋습니다.
        // 마이페이지 업데이트 시에도 id, email, phone의 고유성 제약조건을 지켜야 합니다.

        const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true });
        
        // 세션 정보 업데이트
        req.session.user.name = updatedUser.name;
        // id는 고유해야 하므로 변경하지 않습니다. (id 필드는 마이페이지에서 수정되지 않음)
        // req.session.user.id = updatedUser.id; 
        
        res.redirect("/mypage");
    } catch (error) {
        // 마이페이지 업데이트 중 중복 키 오류(E11000) 발생 시 처리
        if (error.code === 11000) {
             // 예를 들어, 다른 사용자가 이미 사용 중인 이메일/전화번호로 변경하려 했을 때
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

// index.js (라우터 하단에 추가)

// --- 4. 행복 찾기(Happy Find) 및 챌린지 관련 라우트 ---

// GET /happy-find: 행복 찾기 허브 (챌린지 목록, 랜덤 발견 버튼)
router.get("/happy-find", async (req, res) => {
    try {
        const user = req.session.user; 
        if (!user) return res.redirect("/login");

        const allChallenges = await Challenge.find({ isActive: true }).sort({ startDate: -1 });
        
        const fullUser = await User.findOne({ id: user.id })
            .populate('joinedChallenges.challengeId'); 
        
        // 사용자가 작성한 모든 일기 목록을 가져와서 현재 진행도 계산용으로 사용
        const userPosts = await Post.find({ authorId: user.id, challengeId: { $ne: null } });

        const challengesWithStatus = allChallenges.map(c => {
            // 사용자 정보에서 해당 챌린지의 상태 객체를 찾습니다.
            const userChallenge = fullUser.joinedChallenges.find(
                jc => jc.challengeId && jc.challengeId._id.equals(c._id) 
            );

            let status = '미참여';
            let currentPostsCount = 0;

            if (userChallenge) {
                // 1. 기본 상태는 '참여 중'으로 설정
                status = '참여 중'; 

                // 2. 현재 일기 작성 개수를 계산
                currentPostsCount = userPosts.filter(
                    // c._id는 Challenge 모델에서 가져온 ObjectId, Post의 challengeId도 ObjectId로 가정
                    p => p.challengeId && p.challengeId.equals(c._id)
                ).length;
                
                // 3. 핵심 수정: 일기 개수로 성공 여부를 재검증합니다.
                if (currentPostsCount >= c.duration) {
                    status = '챌린지 성공';
                } 
                // 4. 만약 DB에 SUCCESS로 저장되어 있어도, 일기 개수가 부족하면 '참여 중'으로 표시됩니다.
            }

            return {
                ...c.toObject(),
                currentPostsCount: currentPostsCount,
                status: status // '미참여', '참여 중', '챌린지 성공' 중 하나 (DB 기반 또는 기본값)
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
        // User 모델에서 현재 사용자의 joinedChallenges 배열에 challengeId를 추가합니다.
        const updateResult = await User.updateOne(
            { id: user.id, 'joinedChallenges.challengeId': { $ne: challengeId } }, // 중복 방지
            { $push: { 
                joinedChallenges: { 
                    challengeId: challengeId,
                    status: '진행중' // DB에 참여 상태 명시
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
        // Mongoose의 $pull 연산자를 사용하여, joinedChallenges 배열에서 
        // challengeId가 일치하는 객체를 찾아서 제거합니다.
        await User.updateOne(
            { id: user.id },
            { 
                $pull: { 
                    joinedChallenges: { 
                        challengeId: challengeId // 해당 챌린지 ID를 가진 객체만 배열에서 제거
                    } 
                } 
            }
        );

        // 참고: 이 작업은 참여 기록만 지우며, 사용자가 이 챌린지로 작성했던 일기(Post)는 유지됩니다.
        // 만약 일기까지 모두 삭제하려면 Post.deleteMany(...) 코드를 추가해야 합니다.

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
            // 1. 필터링: 공개 글(isPublic: true)만 선택
            { $match: { isPublic: true } },
            
            // 2. 무작위 추출: 1개의 문서를 무작위로 선택 (MongoDB의 강력한 기능)
            { $sample: { size: 1 } },
            
            // 3. 작성자 정보 결합 (랜덤 노출 동의 여부 확인을 위해)
            {
                $lookup: {
                    from: 'users',      // MongoDB 컬렉션 이름 (일반적으로 소문자 복수형)
                    localField: 'authorId', 
                    foreignField: 'id', // Post에 저장된 authorId가 User의 id 필드와 일치한다고 가정
                    as: 'authorInfo'
                }
            },
            // 4. 정보 가공: 노출 필터링
            {
                $project: {
                    _id: 1,
                    title: 1,
                    content: 1,
                    imageUrl: 1,
                    createdAt: 1,
                    // 익명 처리 로직
                    authorId: {
                        $cond: {
                            if: { $eq: [{ $arrayElemAt: ["$authorInfo.isRandomExposed", 0] }, false] },
                            then: "익명의 행복 전도사", // 랜덤 노출 비동의 시 익명 처리
                            else: "$authorId" // 동의 시 닉네임 사용
                        }
                    }
                }
            }
        ]);

        if (randomPost) {
            // 새로운 템플릿으로 렌더링
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

module.exports = router;