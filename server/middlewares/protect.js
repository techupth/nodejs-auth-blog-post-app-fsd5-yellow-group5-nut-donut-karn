import jwt from "jsonwebtoken";

// 🐨 Todo: Exercise #5
// สร้าง Middleware ขึ้นมา 1 อันชื่อ Function ว่า `protect`
// เพื่อเอาไว้ตรวจสอบว่า Client แนบ Token มาใน Header ของ Request หรือไม่

function protect(req, res, next) {
  // ถ้า Client ไม่ได้แนบ Token มาก็ให้ Server Return ตัว Response ว่า Please send me a JWT token
  const token = req.headers.authorization;

  if (!token || !token.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Please send me a JWT token",
    });
  }

  // ถ้า Verify ตัว Token แล้วมี Error ก็ให้ Return ตัว Response กลับไปหา Client ว่า
  // JWT token is invalid
  const tokenWithoutBearer = token.split(" ")[1];

  jwt.verify(tokenWithoutBearer, process.env.SECRET_KEY, (err, payload) => {
    if (err) {
      return res.status(401).json({
        message: "JWT token is invalid",
      });
    }
    req.user = payload;
    next();
  });
}

export default protect;
