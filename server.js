import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const today = () => new Date().toISOString().slice(0, 10);

/* ---------------- DATABASE ---------------- */
const db = new Database(path.join(__dirname, "ssms.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL, name TEXT NOT NULL,
  student_id INTEGER, child_id INTEGER
);
CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, roll TEXT NOT NULL,
  cls TEXT NOT NULL, parent TEXT, contact TEXT
);
CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, role TEXT NOT NULL,
  subject TEXT, cls TEXT
);
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
  date TEXT NOT NULL, status TEXT NOT NULL, UNIQUE(student_id, date)
);
CREATE TABLE IF NOT EXISTS fees (
  student_id INTEGER PRIMARY KEY, total INTEGER NOT NULL DEFAULT 0, paid INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS marks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
  subject TEXT NOT NULL, score INTEGER NOT NULL, UNIQUE(student_id, subject)
);
CREATE TABLE IF NOT EXISTS notices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT, date TEXT NOT NULL
);
`);

function seedIfEmpty() {
  const { c } = db.prepare("SELECT COUNT(*) c FROM users").get();
  if (c > 0) return;

  const hash = (pw) => bcrypt.hashSync(pw, 10);
  const insStudent = db.prepare("INSERT INTO students (name, roll, cls, parent, contact) VALUES (?,?,?,?,?)");
  const rows = [
    ["Ananya Rao", "10A-01", "10-A", "Suresh Rao", "98450 11223"],
    ["Vikram Shah", "10A-02", "10-A", "Meena Shah", "98450 33445"],
    ["Fatima Sheikh", "9B-01", "9-B", "Imran Sheikh", "98450 55667"],
    ["Rohan Verma", "9B-02", "9-B", "Alka Verma", "98450 77889"],
    ["Diya Nair", "8C-01", "8-C", "Ravi Nair", "98450 99001"],
  ];
  const ids = rows.map((r) => insStudent.run(...r).lastInsertRowid);

  const insStaff = db.prepare("INSERT INTO staff (name, role, subject, cls) VALUES (?,?,?,?)");
  insStaff.run("Mrs. Kavita Iyer", "Teacher", "Mathematics", "10-A");
  insStaff.run("Mr. Arjun Menon", "Teacher", "Science", "9-B");
  insStaff.run("Ms. Priya Das", "Teacher", "English", "8-C");
  insStaff.run("Mr. Sanjay Gupta", "Accountant", "-", "-");

  const insAtt = db.prepare("INSERT INTO attendance (student_id, date, status) VALUES (?,?,?)");
  ids.forEach((id, i) => insAtt.run(id, today(), i === 3 ? "absent" : "present"));

  const insFee = db.prepare("INSERT INTO fees (student_id, total, paid) VALUES (?,?,?)");
  ids.forEach((id, i) => insFee.run(id, 25000, i % 2 === 0 ? 25000 : 15000));

  const insMark = db.prepare("INSERT INTO marks (student_id, subject, score) VALUES (?,?,?)");
  ["Maths", "Science", "English"].forEach((sub) =>
    ids.forEach((id) => insMark.run(id, sub, 60 + Math.floor(Math.random() * 35)))
  );

  db.prepare("INSERT INTO notices (title, body, date) VALUES (?,?,?)").run(
    "PTA Meeting - Aug 2", "Parent-teacher meeting for all classes at 10 AM in the auditorium.", today()
  );
  db.prepare("INSERT INTO notices (title, body, date) VALUES (?,?,?)").run(
    "Fee Deadline Reminder", "Term-2 fees are due by the end of this month.", today()
  );

  const insUser = db.prepare("INSERT INTO users (username, password_hash, role, name, student_id, child_id) VALUES (?,?,?,?,?,?)");
  insUser.run("admin", hash("demo1234"), "admin", "School Admin", null, null);
  insUser.run("kavita.iyer", hash("demo1234"), "teacher", "Mrs. Kavita Iyer", null, null);
  insUser.run("ananya.rao", hash("demo1234"), "student", "Ananya Rao", ids[0], null);
  insUser.run("suresh.rao", hash("demo1234"), "parent", "Suresh Rao", null, ids[0]);
}
seedIfEmpty();

/* ---------------- AUTH HELPERS ---------------- */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid or expired token" }); }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Not permitted for this role" });
    next();
  };
}

/* ---------------- APP ---------------- */
const app = express();
app.use(cors());
app.use(express.json());

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid username or password" });
  }
  const payload = { id: user.id, username: user.username, role: user.role, name: user.name, studentId: user.student_id, childId: user.child_id };
  const token = jwt.sign(payload, SECRET, { expiresIn: "12h" });
  res.json({ token, user: payload });
});

app.get("/api/students", requireAuth, requireRole("admin", "teacher"), (req, res) => {
  res.json(db.prepare("SELECT * FROM students ORDER BY cls, roll").all());
});
app.post("/api/students", requireAuth, requireRole("admin"), (req, res) => {
  const { name, roll, cls, parent, contact } = req.body || {};
  if (!name || !roll || !cls) return res.status(400).json({ error: "name, roll, cls required" });
  const info = db.prepare("INSERT INTO students (name, roll, cls, parent, contact) VALUES (?,?,?,?,?)").run(name, roll, cls, parent || "", contact || "");
  db.prepare("INSERT INTO fees (student_id, total, paid) VALUES (?,0,0)").run(info.lastInsertRowid);
  res.status(201).json(db.prepare("SELECT * FROM students WHERE id=?").get(info.lastInsertRowid));
});
app.put("/api/students/:id", requireAuth, requireRole("admin"), (req, res) => {
  const ex = db.prepare("SELECT * FROM students WHERE id=?").get(req.params.id);
  if (!ex) return res.status(404).json({ error: "Not found" });
  const { name, roll, cls, parent, contact } = req.body || {};
  db.prepare("UPDATE students SET name=?, roll=?, cls=?, parent=?, contact=? WHERE id=?")
    .run(name ?? ex.name, roll ?? ex.roll, cls ?? ex.cls, parent ?? ex.parent, contact ?? ex.contact, req.params.id);
  res.json(db.prepare("SELECT * FROM students WHERE id=?").get(req.params.id));
});
app.delete("/api/students/:id", requireAuth, requireRole("admin"), (req, res) => {
  db.prepare("DELETE FROM students WHERE id=?").run(req.params.id);
  res.status(204).end();
});

app.get("/api/staff", requireAuth, requireRole("admin"), (req, res) => {
  res.json(db.prepare("SELECT * FROM staff ORDER BY name").all());
});

app.get("/api/attendance", requireAuth, (req, res) => {
  const { role, studentId, childId } = req.user;
  if (role === "admin" || role === "teacher") return res.json(db.prepare("SELECT * FROM attendance").all());
  const id = role === "student" ? studentId : childId;
  res.json(id ? db.prepare("SELECT * FROM attendance WHERE student_id=?").all(id) : []);
});
app.post("/api/attendance", requireAuth, requireRole("admin", "teacher"), (req, res) => {
  const { studentId, date, status } = req.body || {};
  if (!studentId || !date || !["present", "absent"].includes(status)) return res.status(400).json({ error: "Invalid body" });
  db.prepare(`INSERT INTO attendance (student_id, date, status) VALUES (?,?,?)
    ON CONFLICT(student_id, date) DO UPDATE SET status=excluded.status`).run(studentId, date, status);
  res.json({ studentId, date, status });
});

app.get("/api/fees", requireAuth, (req, res) => {
  const { role, studentId, childId } = req.user;
  if (role === "admin") return res.json(db.prepare("SELECT f.*, s.name FROM fees f JOIN students s ON s.id=f.student_id").all());
  const id = role === "student" ? studentId : childId;
  res.json(id ? db.prepare("SELECT f.*, s.name FROM fees f JOIN students s ON s.id=f.student_id WHERE f.student_id=?").all(id) : []);
});
app.post("/api/fees/:studentId/pay", requireAuth, requireRole("admin"), (req, res) => {
  db.prepare("UPDATE fees SET paid=total WHERE student_id=?").run(req.params.studentId);
  res.json(db.prepare("SELECT * FROM fees WHERE student_id=?").get(req.params.studentId));
});

app.get("/api/marks", requireAuth, (req, res) => {
  const { role, studentId, childId } = req.user;
  if (role === "admin" || role === "teacher") return res.json(db.prepare("SELECT * FROM marks").all());
  const id = role === "student" ? studentId : childId;
  res.json(id ? db.prepare("SELECT * FROM marks WHERE student_id=?").all(id) : []);
});
app.post("/api/marks", requireAuth, requireRole("admin", "teacher"), (req, res) => {
  const { studentId, subject, score } = req.body || {};
  const num = Math.max(0, Math.min(100, Number(score)));
  if (!studentId || !subject || Number.isNaN(num)) return res.status(400).json({ error: "Invalid body" });
  db.prepare(`INSERT INTO marks (student_id, subject, score) VALUES (?,?,?)
    ON CONFLICT(student_id, subject) DO UPDATE SET score=excluded.score`).run(studentId, subject, num);
  res.json({ studentId, subject, score: num });
});

app.get("/api/notices", requireAuth, (req, res) => {
  res.json(db.prepare("SELECT * FROM notices ORDER BY id DESC").all());
});
app.post("/api/notices", requireAuth, requireRole("admin", "teacher"), (req, res) => {
  const { title, body } = req.body || {};
  if (!title) return res.status(400).json({ error: "title required" });
  const info = db.prepare("INSERT INTO notices (title, body, date) VALUES (?,?,?)").run(title, body || "", today());
  res.status(201).json(db.prepare("SELECT * FROM notices WHERE id=?").get(info.lastInsertRowid));
});

// static frontend (single HTML file, no build step)
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api")) return next();
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, "0.0.0.0", () => console.log(`SSMS running on http://localhost:${PORT}`));