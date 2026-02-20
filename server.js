/**
 * RENTAX Backend Server - MongoDB Production Version
 * Complete API for Super Admin Functionality with Performance Optimizations
 *
 * Features:
 * - MongoDB with Mongoose ORM
 * - User Management (CRUD)
 * - Client Management (CRUD)
 * - Onboarding Approval Queue
 * - Department Management
 * - System Settings & Configuration
 * - Audit Log Viewer
 * - Authentication & Authorization
 * - Role-based Access Control
 * - Performance Optimizations (Compression, Rate Limiting, Helmet, Connection Pooling)
 *
 * @version 2.0.0
 * @author RENTAX Development Team
 */

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Initialize Express
const app = express();

// ✅ Trust proxy - Required for Digital Ocean App Platform and other reverse proxies
// This allows Express to correctly read X-Forwarded-For headers for rate limiting and logging
app.set("trust proxy", true);

const PORT = process.env.PORT || 5000;
const JWT_SECRET =
  process.env.JWT_SECRET || "rentax-super-secret-key-change-in-production";
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/rentax";

// ============================================================================
// MONGOOSE SCHEMAS & MODELS
// ============================================================================

// User Schema
const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: { type: String, required: true },
    name: { type: String, required: true },
    role: {
      type: String,
      enum: [
        "super_admin",
        "operational_manager",
        "supervisor",
        "head_of_department",
        "staff",
        "business_owner",
        "business_manager",
        "business_staff",
      ],
      required: true,
    },
    department: {
      type: String,
      enum: ["compliance", "tax", "accounts", "audit", "marketing", "legal"],
      required: true,
    },
    phone: { type: String, default: "" },
    status: {
      type: String,
      enum: ["active", "inactive", "suspended"],
      default: "active",
    },
    lastLogin: { type: Date },
  },
  { timestamps: true },
);

// Index for faster queries (email index automatically created by unique: true)
userSchema.index({ role: 1 });
userSchema.index({ department: 1 });
userSchema.index({ status: 1 });

const User = mongoose.model("User", userSchema);

// Client Schema
const clientSchema = new mongoose.Schema(
  {
    businessName: { type: String, required: true },
    contactPerson: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    package: {
      type: String,
      enum: ["silver", "gold", "platinum"],
      required: true,
    },
    serviceType: { type: String, enum: ["one_time", "annual"], required: true },
    status: {
      type: String,
      enum: ["active", "inactive", "suspended"],
      default: "active",
    },
    onboardingStatus: { type: String, default: "active" },
    registrationDate: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now },
    mrr: { type: Number, default: 0 },
    complianceScore: { type: Number, default: 85, min: 0, max: 100 },
    businessSize: { type: String, enum: ["micro", "small", "medium", "large"] },
    industry: { type: String },
    tenantId: { type: String, unique: true },
  },
  { timestamps: true },
);

// Indexes for performance (tenantId index automatically created by unique: true)
clientSchema.index({ email: 1 });
clientSchema.index({ package: 1 });
clientSchema.index({ serviceType: 1 });
clientSchema.index({ status: 1 });

const Client = mongoose.model("Client", clientSchema);

// Onboarding Application Schema
const onboardingApplicationSchema = new mongoose.Schema(
  {
    businessName: { type: String, required: true },
    contactPerson: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    selectedPackage: {
      type: String,
      enum: ["silver", "gold", "platinum"],
      required: true,
    },
    serviceType: { type: String, enum: ["one_time", "annual"], required: true },
    businessSize: { type: String, enum: ["micro", "small", "medium", "large"] },
    industry: { type: String },
    status: {
      type: String,
      enum: ["pending", "under_review", "approved", "rejected"],
      default: "pending",
    },
    submittedAt: { type: Date, default: Date.now },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    reviewedAt: { type: Date },
    approvalNotes: { type: String },
    rejectionReason: { type: String },
  },
  { timestamps: true },
);

onboardingApplicationSchema.index({ status: 1 });
onboardingApplicationSchema.index({ email: 1 });

const OnboardingApplication = mongoose.model(
  "OnboardingApplication",
  onboardingApplicationSchema,
);

// Department Schema
const departmentSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    code: { type: String, required: true, unique: true },
    description: { type: String },
    headOfDepartment: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    staffCount: { type: Number, default: 0 },
    activeClients: { type: Number, default: 0 },
    pendingTasks: { type: Number, default: 0 },
    completedTasks: { type: Number, default: 0 },
  },
  { timestamps: true },
);

// Indexes for performance (code index automatically created by unique: true)

const Department = mongoose.model("Department", departmentSchema);

// System Settings Schema
const systemSettingsSchema = new mongoose.Schema(
  {
    settingKey: { type: String, required: true, unique: true },
    settingValue: { type: mongoose.Schema.Types.Mixed, required: true },
    category: { type: String },
    description: { type: String },
  },
  { timestamps: true },
);

// Indexes for performance (settingKey index automatically created by unique: true)

const SystemSettings = mongoose.model("SystemSettings", systemSettingsSchema);

// Audit Log Schema
const auditLogSchema = new mongoose.Schema(
  {
    entityType: {
      type: String,
      enum: ["task", "client", "user", "financial", "system", "department"],
      required: true,
    },
    entityId: { type: String, required: true },
    action: { type: String, required: true },
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    performedByName: { type: String, required: true },
    performedByRole: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    changes: [
      {
        field: String,
        oldValue: mongoose.Schema.Types.Mixed,
        newValue: mongoose.Schema.Types.Mixed,
      },
    ],
    metadata: { type: mongoose.Schema.Types.Mixed },
  },
  { timestamps: true },
);

// Indexes for fast filtering
auditLogSchema.index({ entityType: 1 });
auditLogSchema.index({ action: 1 });
auditLogSchema.index({ performedBy: 1 });
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ "metadata.department": 1 });

const AuditLog = mongoose.model("AuditLog", auditLogSchema);

// ============================================================================
// DATABASE CONNECTION WITH POOLING
// ============================================================================

mongoose
  .connect(MONGODB_URI, {
    maxPoolSize: 10, // Maximum number of connections in the pool
    minPoolSize: 2, // Minimum number of connections
    socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    serverSelectionTimeoutMS: 30000, // ✅ Increased to 30s for Digital Ocean
    connectTimeoutMS: 30000, // ✅ Added: Connection timeout
    family: 4, // Use IPv4, skip trying IPv6
    retryWrites: true, // ✅ Added: Retry failed writes
    retryReads: true, // ✅ Added: Retry failed reads
  })
  .then(() => {
    console.log("✅ MongoDB connected successfully with connection pooling");
    console.log(`   Database: ${MONGODB_URI.split("/").pop()}`);
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    console.error("   Please check:");
    console.error("   1. MONGODB_URI environment variable is set");
    console.error("   2. MongoDB trusted sources include this server");
    console.error("   3. Connection string includes replicaSet parameter");
    process.exit(1);
  });

// Connection event handlers
mongoose.connection.on("connected", () => {
  console.log("📡 Mongoose connected to MongoDB");
});

mongoose.connection.on("error", (err) => {
  console.error("❌ Mongoose connection error:", err);
});

mongoose.connection.on("disconnected", () => {
  console.log("⚠️  Mongoose disconnected from MongoDB");
});

// Graceful shutdown
process.on("SIGINT", async () => {
  await mongoose.connection.close();
  console.log("🛑 Mongoose connection closed due to application termination");
  process.exit(0);
});

// ============================================================================
// PERFORMANCE & SECURITY MIDDLEWARE
// ============================================================================

// 1. Helmet - Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);

// 2. CORS - Cross-Origin Resource Sharing
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : [
      "http://localhost:5173",
      "http://localhost:3000",
      "https://rentax.co.tz",
      "https://www.rentax.co.tz",
    ];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);

      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  }),
);

// 3. Compression - Gzip compression
app.use(
  compression({
    level: 6, // Compression level (0-9)
    threshold: 1024, // Only compress responses > 1KB
    filter: (req, res) => {
      if (req.headers["x-no-compression"]) {
        return false;
      }
      return compression.filter(req, res);
    },
  }),
);

// 4. Rate Limiting - Prevent abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
  // ✅ Validate trust proxy configuration for production deployment
  validate: { trustProxy: false }, // Disable validation - we trust Digital Ocean's proxy
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  message: "Too many login attempts, please try again later",
  skipSuccessfulRequests: true,
  // ✅ Validate trust proxy configuration for production deployment
  validate: { trustProxy: false }, // Disable validation - we trust Digital Ocean's proxy
});

app.use("/api/", apiLimiter);
app.use("/api/auth/login", authLimiter);

// 5. Body parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// 6. MongoDB injection prevention (Custom middleware - no package dependency)
const sanitizeInput = (req, res, next) => {
  const sanitize = (obj) => {
    if (!obj || typeof obj !== "object") return obj;

    for (let key in obj) {
      // ✅ FIX: Use Object.prototype.hasOwnProperty.call instead of obj.hasOwnProperty
      // This prevents errors when obj doesn't have hasOwnProperty in its prototype chain
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        if (typeof obj[key] === "string") {
          obj[key] = obj[key].replace(/[${}]/g, "");
        } else if (typeof obj[key] === "object" && obj[key] !== null) {
          sanitize(obj[key]);
        }
        if (key.startsWith("$")) {
          delete obj[key];
        }
      }
    }
    return obj;
  };

  if (req.body) req.body = sanitize(req.body);
  if (req.query) req.query = sanitize(req.query);
  if (req.params) req.params = sanitize(req.params);

  next();
};

app.use(sanitizeInput);

// 7. Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Audit logger
async function logAudit(
  entityType,
  entityId,
  action,
  user,
  changes = null,
  metadata = {},
) {
  try {
    const auditLog = new AuditLog({
      entityType,
      entityId,
      action,
      performedBy: user._id || user.id,
      performedByName: user.name,
      performedByRole: user.role,
      timestamp: new Date(),
      changes,
      metadata: {
        ...metadata,
        department: user.department,
      },
    });

    await auditLog.save();
    return auditLog;
  } catch (error) {
    console.error("Audit log error:", error);
  }
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (user.status !== "active") {
      return res.status(403).json({ error: "Account is not active" });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Create token
    const token = jwt.sign(
      {
        id: user._id.toString(),
        _id: user._id.toString(),
        email: user.email,
        role: user.role,
        name: user.name,
        department: user.department,
      },
      JWT_SECRET,
      { expiresIn: "24h" },
    );

    // Log audit
    await logAudit("user", user._id.toString(), "user_login", user);

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
        status: user.status,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get current user
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      department: user.department,
      status: user.status,
    });
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Logout
app.post("/api/auth/logout", authenticateToken, async (req, res) => {
  try {
    await logAudit("user", req.user.id, "user_logout", req.user);
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================================================
// USER MANAGEMENT ROUTES
// ============================================================================

// Get all users
app.get(
  "/api/users",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const {
        search,
        role,
        department,
        status,
        page = 1,
        limit = 50,
      } = req.query;

      const query = {};

      // Apply filters
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ];
      }

      if (role) query.role = role;
      if (department) query.department = department;
      if (status) query.status = status;

      const users = await User.find(query)
        .select("-password")
        .limit(parseInt(limit))
        .skip((parseInt(page) - 1) * parseInt(limit))
        .sort({ createdAt: -1 });

      const total = await User.countDocuments(query);

      // Calculate statistics
      const enterpriseRoles = [
        "business_owner",
        "business_manager",
        "business_staff",
      ];
      const stats = {
        total: await User.countDocuments(),
        active: await User.countDocuments({ status: "active" }),
        inactive: await User.countDocuments({ status: "inactive" }),
        suspended: await User.countDocuments({ status: "suspended" }),
        firmUsers: await User.countDocuments({
          role: { $nin: enterpriseRoles },
        }),
        enterpriseUsers: await User.countDocuments({
          role: { $in: enterpriseRoles },
        }),
      };

      res.json({
        users,
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        stats,
      });
    } catch (error) {
      console.error("Get users error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Get user by ID
app.get("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create user
app.post(
  "/api/users",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { email, name, role, department, password } = req.body;

      // Validation
      if (!email || !name || !role || !department || !password) {
        return res.status(400).json({ error: "All fields required" });
      }

      // Name validation
      if (name.trim().length < 2) {
        return res
          .status(400)
          .json({ error: "Name must be at least 2 characters" });
      }

      // Email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ error: "Invalid email format" });
      }

      // Password validation
      if (password.length < 6) {
        return res
          .status(400)
          .json({ error: "Password must be at least 6 characters" });
      }

      // Check if email exists
      const existingUser = await User.findOne({ email: email.toLowerCase() });
      if (existingUser) {
        return res.status(400).json({ error: "Email already exists" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user
      const newUser = new User({
        email: email.toLowerCase().trim(),
        name: name.trim(),
        role,
        department,
        password: hashedPassword,
        status: "active",
      });

      await newUser.save();

      // Log audit
      await logAudit(
        "user",
        newUser._id.toString(),
        "user_created",
        req.user,
        null,
        {
          newUserEmail: email,
          newUserRole: role,
        },
      );

      const userResponse = newUser.toObject();
      delete userResponse.password;

      res.status(201).json(userResponse);
    } catch (error) {
      console.error("Create user error:", error);

      // Handle MongoDB validation errors
      if (error.name === "ValidationError") {
        return res
          .status(400)
          .json({ error: "Validation failed: " + error.message });
      }

      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Update user
app.put(
  "/api/users/:id",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, role, department, status, phone } = req.body;

      const user = await User.findById(id);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const changes = [];

      // Track changes
      if (name && name !== user.name) {
        changes.push({ field: "name", oldValue: user.name, newValue: name });
        user.name = name;
      }

      if (role && role !== user.role) {
        changes.push({ field: "role", oldValue: user.role, newValue: role });
        user.role = role;
      }

      if (department && department !== user.department) {
        changes.push({
          field: "department",
          oldValue: user.department,
          newValue: department,
        });
        user.department = department;
      }

      if (status && status !== user.status) {
        changes.push({
          field: "status",
          oldValue: user.status,
          newValue: status,
        });
        user.status = status;
      }

      if (phone !== undefined && phone !== user.phone) {
        changes.push({ field: "phone", oldValue: user.phone, newValue: phone });
        user.phone = phone;
      }

      await user.save();

      // Log audit
      if (changes.length > 0) {
        await logAudit("user", id, "user_updated", req.user, changes);
      }

      const userResponse = user.toObject();
      delete userResponse.password;

      res.json(userResponse);
    } catch (error) {
      console.error("Update user error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Delete user
app.delete(
  "/api/users/:id",
  authenticateToken,
  requireRole("super_admin"),
  async (req, res) => {
    try {
      const { id } = req.params;

      const user = await User.findById(id);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Prevent deleting yourself
      if (id === req.user.id) {
        return res
          .status(400)
          .json({ error: "Cannot delete your own account" });
      }

      await User.findByIdAndDelete(id);

      // Log audit
      await logAudit("user", id, "user_deleted", req.user, null, {
        deletedUserEmail: user.email,
        deletedUserRole: user.role,
      });

      res.json({ message: "User deleted successfully" });
    } catch (error) {
      console.error("Delete user error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ============================================================================
// CLIENT MANAGEMENT ROUTES
// ============================================================================

// Get all clients
app.get("/api/clients", authenticateToken, async (req, res) => {
  try {
    const {
      search,
      package: pkg,
      serviceType,
      status,
      businessSize,
      page = 1,
      limit = 50,
    } = req.query;

    const query = {};

    // Apply filters
    if (search) {
      query.$or = [
        { businessName: { $regex: search, $options: "i" } },
        { contactPerson: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
      ];
    }

    if (pkg) query.package = pkg;
    if (serviceType) query.serviceType = serviceType;
    if (status) query.status = status;
    if (businessSize) query.businessSize = businessSize;

    const clients = await Client.find(query)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .sort({ createdAt: -1 });

    const total = await Client.countDocuments(query);

    // Calculate statistics
    const allClients = await Client.find(query);
    const stats = {
      silver: allClients.filter((c) => c.package === "silver").length,
      gold: allClients.filter((c) => c.package === "gold").length,
      platinum: allClients.filter((c) => c.package === "platinum").length,
      active: allClients.filter((c) => c.status === "active").length,
      totalMRR: allClients.reduce((sum, c) => sum + c.mrr, 0),
    };

    res.json({
      clients,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
      stats,
    });
  } catch (error) {
    console.error("Get clients error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get client by ID
app.get("/api/clients/:id", authenticateToken, async (req, res) => {
  try {
    const client = await Client.findById(req.params.id);

    if (!client) {
      return res.status(404).json({ error: "Client not found" });
    }

    res.json(client);
  } catch (error) {
    console.error("Get client error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update client
app.put(
  "/api/clients/:id",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      const client = await Client.findById(id);

      if (!client) {
        return res.status(404).json({ error: "Client not found" });
      }

      const changes = [];

      // Track changes
      Object.keys(updates).forEach((key) => {
        if (updates[key] !== client[key]) {
          changes.push({
            field: key,
            oldValue: client[key],
            newValue: updates[key],
          });
          client[key] = updates[key];
        }
      });

      await client.save();

      // Log audit
      if (changes.length > 0) {
        await logAudit("client", id, "client_updated", req.user, changes);
      }

      res.json(client);
    } catch (error) {
      console.error("Update client error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ============================================================================
// ONBOARDING APPROVAL QUEUE ROUTES
// ============================================================================

// Get all onboarding applications
app.get(
  "/api/onboarding",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { status, package: pkg, page = 1, limit = 50 } = req.query;

      const query = {};

      if (status) query.status = status;
      if (pkg) query.selectedPackage = pkg;

      const applications = await OnboardingApplication.find(query)
        .populate("reviewedBy", "name email")
        .limit(parseInt(limit))
        .skip((parseInt(page) - 1) * parseInt(limit))
        .sort({ submittedAt: -1 });

      const total = await OnboardingApplication.countDocuments(query);

      // Calculate statistics
      const stats = {
        pending: await OnboardingApplication.countDocuments({
          status: "pending",
        }),
        under_review: await OnboardingApplication.countDocuments({
          status: "under_review",
        }),
        approved: await OnboardingApplication.countDocuments({
          status: "approved",
        }),
        rejected: await OnboardingApplication.countDocuments({
          status: "rejected",
        }),
      };

      res.json({
        applications,
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        stats,
      });
    } catch (error) {
      console.error("Get onboarding error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Get application by ID
app.get(
  "/api/onboarding/:id",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const application = await OnboardingApplication.findById(
        req.params.id,
      ).populate("reviewedBy", "name email");

      if (!application) {
        return res.status(404).json({ error: "Application not found" });
      }

      res.json(application);
    } catch (error) {
      console.error("Get application error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Approve application
app.post(
  "/api/onboarding/:id/approve",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { notes } = req.body;

      const application = await OnboardingApplication.findById(id);

      if (!application) {
        return res.status(404).json({ error: "Application not found" });
      }

      if (application.status === "approved") {
        return res.status(400).json({ error: "Application already approved" });
      }

      // Update application
      application.status = "approved";
      application.reviewedBy = req.user.id;
      application.reviewedAt = new Date();
      application.approvalNotes = notes || "Application approved";

      await application.save();

      // Create new client
      const newClient = new Client({
        businessName: application.businessName,
        contactPerson: application.contactPerson,
        email: application.email,
        phone: application.phone,
        package: application.selectedPackage,
        serviceType: application.serviceType,
        status: "active",
        onboardingStatus: "active",
        registrationDate: new Date(),
        lastActivity: new Date(),
        mrr:
          application.selectedPackage === "silver"
            ? 50000
            : application.selectedPackage === "gold"
              ? 150000
              : 300000,
        complianceScore: 85,
        businessSize: application.businessSize,
        industry: application.industry,
        tenantId: `tenant-${newClient._id}`,
      });

      await newClient.save();

      // Log audit
      await logAudit(
        "client",
        newClient._id.toString(),
        "client_approved",
        req.user,
        null,
        {
          applicationId: id,
          businessName: application.businessName,
        },
      );

      res.json({
        application,
        client: newClient,
      });
    } catch (error) {
      console.error("Approve application error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Reject application
app.post(
  "/api/onboarding/:id/reject",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { reason } = req.body;

      if (!reason) {
        return res.status(400).json({ error: "Rejection reason required" });
      }

      const application = await OnboardingApplication.findById(id);

      if (!application) {
        return res.status(404).json({ error: "Application not found" });
      }

      if (application.status === "rejected") {
        return res.status(400).json({ error: "Application already rejected" });
      }

      // Update application
      application.status = "rejected";
      application.reviewedBy = req.user.id;
      application.reviewedAt = new Date();
      application.rejectionReason = reason;

      await application.save();

      // Log audit
      await logAudit("client", id, "client_rejected", req.user, null, {
        businessName: application.businessName,
        reason,
      });

      res.json(application);
    } catch (error) {
      console.error("Reject application error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ============================================================================
// DEPARTMENT MANAGEMENT ROUTES
// ============================================================================

// Get all departments
app.get("/api/departments", authenticateToken, async (req, res) => {
  try {
    const departments = await Department.find()
      .populate("headOfDepartment", "name email")
      .sort({ name: 1 });

    res.json({
      departments,
      total: departments.length,
    });
  } catch (error) {
    console.error("Get departments error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get department by ID
app.get("/api/departments/:id", authenticateToken, async (req, res) => {
  try {
    const department = await Department.findById(req.params.id).populate(
      "headOfDepartment",
      "name email",
    );

    if (!department) {
      return res.status(404).json({ error: "Department not found" });
    }

    res.json(department);
  } catch (error) {
    console.error("Get department error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create department
app.post(
  "/api/departments",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { name, code, description, headOfDepartment } = req.body;

      if (!name || !code) {
        return res.status(400).json({ error: "Name and code required" });
      }

      // Check if code exists
      const existingDept = await Department.findOne({ code });
      if (existingDept) {
        return res
          .status(400)
          .json({ error: "Department code already exists" });
      }

      const newDepartment = new Department({
        name,
        code,
        description: description || "",
        headOfDepartment: headOfDepartment || null,
        staffCount: 0,
        activeClients: 0,
        pendingTasks: 0,
        completedTasks: 0,
      });

      await newDepartment.save();

      // Log audit
      await logAudit(
        "department",
        newDepartment._id.toString(),
        "department_created",
        req.user,
        null,
        {
          departmentName: name,
        },
      );

      res.status(201).json(newDepartment);
    } catch (error) {
      console.error("Create department error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Update department
app.put(
  "/api/departments/:id",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      const department = await Department.findById(id);

      if (!department) {
        return res.status(404).json({ error: "Department not found" });
      }

      const changes = [];

      Object.keys(updates).forEach((key) => {
        if (updates[key] !== department[key]) {
          changes.push({
            field: key,
            oldValue: department[key],
            newValue: updates[key],
          });
          department[key] = updates[key];
        }
      });

      await department.save();

      // Log audit
      if (changes.length > 0) {
        await logAudit(
          "department",
          id,
          "department_updated",
          req.user,
          changes,
        );
      }

      res.json(department);
    } catch (error) {
      console.error("Update department error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Delete department
app.delete(
  "/api/departments/:id",
  authenticateToken,
  requireRole("super_admin"),
  async (req, res) => {
    try {
      const { id } = req.params;

      const department = await Department.findById(id);

      if (!department) {
        return res.status(404).json({ error: "Department not found" });
      }

      await Department.findByIdAndDelete(id);

      // Log audit
      await logAudit("department", id, "department_deleted", req.user, null, {
        departmentName: department.name,
      });

      res.json({ message: "Department deleted successfully" });
    } catch (error) {
      console.error("Delete department error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ============================================================================
// SYSTEM SETTINGS ROUTES
// ============================================================================

// Get all system settings
app.get(
  "/api/settings",
  authenticateToken,
  requireRole("super_admin"),
  async (req, res) => {
    try {
      const settings = await SystemSettings.find();

      // Transform to grouped structure
      const groupedSettings = {
        packages: [],
        serviceTypes: [],
        businessClassifications: [],
        emailTemplates: [],
        systemParameters: [],
        featureFlags: [],
      };

      settings.forEach((setting) => {
        if (setting.category && groupedSettings[setting.category]) {
          groupedSettings[setting.category].push(setting.settingValue);
        }
      });

      res.json(groupedSettings);
    } catch (error) {
      console.error("Get settings error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Update specific setting category
app.put(
  "/api/settings/:category",
  authenticateToken,
  requireRole("super_admin"),
  async (req, res) => {
    try {
      const { category } = req.params;
      const { data } = req.body;

      // Update or create setting
      await SystemSettings.findOneAndUpdate(
        { settingKey: category },
        {
          settingKey: category,
          settingValue: data,
          category,
        },
        { upsert: true, new: true },
      );

      // Log audit
      await logAudit("system", category, "settings_updated", req.user, null, {
        settingType: category,
      });

      res.json({ message: "Settings updated successfully" });
    } catch (error) {
      console.error("Update settings error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Legacy endpoints for backwards compatibility
app.put(
  "/api/settings/packages",
  authenticateToken,
  requireRole("super_admin"),
  async (req, res) => {
    return app._router.handle(
      {
        ...req,
        params: { category: "packages" },
        body: { data: req.body.packages },
      },
      res,
    );
  },
);

app.put(
  "/api/settings/service-types",
  authenticateToken,
  requireRole("super_admin"),
  async (req, res) => {
    return app._router.handle(
      {
        ...req,
        params: { category: "serviceTypes" },
        body: { data: req.body.serviceTypes },
      },
      res,
    );
  },
);

// ============================================================================
// AUDIT LOG ROUTES
// ============================================================================

// Get audit logs
app.get(
  "/api/audit-logs",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const {
        search,
        entityType,
        action,
        performedBy,
        department,
        startDate,
        endDate,
        page = 1,
        limit = 100,
      } = req.query;

      const query = {};

      // Apply filters
      if (search) {
        query.$or = [
          { performedByName: { $regex: search, $options: "i" } },
          { action: { $regex: search, $options: "i" } },
          { entityType: { $regex: search, $options: "i" } },
          { entityId: { $regex: search, $options: "i" } },
        ];
      }

      if (entityType) query.entityType = entityType;
      if (action) query.action = action;
      if (performedBy) query.performedBy = performedBy;
      if (department) query["metadata.department"] = department;

      if (startDate) {
        query.timestamp = { $gte: new Date(startDate) };
      }

      if (endDate) {
        query.timestamp = { ...query.timestamp, $lte: new Date(endDate) };
      }

      const logs = await AuditLog.find(query)
        .populate("performedBy", "name email")
        .limit(parseInt(limit))
        .skip((parseInt(page) - 1) * parseInt(limit))
        .sort({ timestamp: -1 });

      const total = await AuditLog.countDocuments(query);

      res.json({
        logs,
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
      });
    } catch (error) {
      console.error("Get audit logs error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Get audit log statistics
app.get(
  "/api/audit-logs/stats",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

      const [total, todayCount, weekCount, byEntityType, byAction] =
        await Promise.all([
          AuditLog.countDocuments(),
          AuditLog.countDocuments({ timestamp: { $gte: today } }),
          AuditLog.countDocuments({ timestamp: { $gte: sevenDaysAgo } }),
          AuditLog.aggregate([
            { $group: { _id: "$entityType", count: { $sum: 1 } } },
          ]),
          AuditLog.aggregate([
            { $group: { _id: "$action", count: { $sum: 1 } } },
          ]),
        ]);

      const criticalActions = [
        "user_deleted",
        "client_rejected",
        "user_role_changed",
        "department_deleted",
      ];
      const critical = await AuditLog.countDocuments({
        action: { $in: criticalActions },
      });

      const stats = {
        total,
        today: todayCount,
        thisWeek: weekCount,
        critical,
        byEntityType: byEntityType.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byAction: byAction.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
      };

      res.json(stats);
    } catch (error) {
      console.error("Get audit stats error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Export audit logs to CSV
app.post(
  "/api/audit-logs/export",
  authenticateToken,
  requireRole("super_admin", "operational_manager"),
  async (req, res) => {
    try {
      const { filters } = req.body;

      const query = {};
      if (filters) {
        if (filters.entityType) query.entityType = filters.entityType;
        if (filters.action) query.action = filters.action;
        if (filters.startDate)
          query.timestamp = { $gte: new Date(filters.startDate) };
        if (filters.endDate)
          query.timestamp = {
            ...query.timestamp,
            $lte: new Date(filters.endDate),
          };
      }

      const logs = await AuditLog.find(query)
        .sort({ timestamp: -1 })
        .limit(1000);

      // Generate CSV
      const csv = [
        [
          "Timestamp",
          "User",
          "Role",
          "Action",
          "Entity Type",
          "Entity ID",
          "Department",
          "Changes",
        ],
        ...logs.map((log) => [
          log.timestamp.toISOString(),
          log.performedByName,
          log.performedByRole,
          log.action,
          log.entityType,
          log.entityId,
          log.metadata?.department || "N/A",
          log.changes ? JSON.stringify(log.changes) : "N/A",
        ]),
      ]
        .map((row) => row.join(","))
        .join("\n");

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=audit-logs-${Date.now()}.csv`,
      );
      res.send(csv);
    } catch (error) {
      console.error("Export audit logs error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ============================================================================
// DASHBOARD & ANALYTICS ROUTES
// ============================================================================

// Get dashboard statistics
app.get("/api/dashboard/stats", authenticateToken, async (req, res) => {
  try {
    const [
      totalClients,
      activeClients,
      pendingApprovals,
      totalUsers,
      totalDepartments,
      recentActivity,
    ] = await Promise.all([
      Client.countDocuments(),
      Client.countDocuments({ status: "active" }),
      OnboardingApplication.countDocuments({ status: "pending" }),
      User.countDocuments(),
      Department.countDocuments(),
      AuditLog.find()
        .sort({ timestamp: -1 })
        .limit(10)
        .populate("performedBy", "name email"),
    ]);

    const clients = await Client.find();
    const totalMRR = clients.reduce((sum, c) => sum + c.mrr, 0);

    const packageDistribution = {
      silver: clients.filter((c) => c.package === "silver").length,
      gold: clients.filter((c) => c.package === "gold").length,
      platinum: clients.filter((c) => c.package === "platinum").length,
    };

    res.json({
      totalClients,
      activeClients,
      pendingApprovals,
      totalUsers,
      totalDepartments,
      totalMRR,
      packageDistribution,
      recentActivity,
    });
  } catch (error) {
    console.error("Get dashboard stats error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get("/health", async (req, res) => {
  try {
    // Check MongoDB connection
    const dbStatus =
      mongoose.connection.readyState === 1 ? "connected" : "disconnected";

    const [userCount, clientCount, auditCount] = await Promise.all([
      User.countDocuments(),
      Client.countDocuments(),
      AuditLog.countDocuments(),
    ]);

    res.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: {
        status: dbStatus,
        users: userCount,
        clients: clientCount,
        auditLogs: auditCount,
      },
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "unhealthy",
      error: error.message,
    });
  }
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);

  // MongoDB validation error
  if (err.name === "ValidationError") {
    return res.status(400).json({
      error: "Validation error",
      details: Object.values(err.errors).map((e) => e.message),
    });
  }

  // MongoDB duplicate key error
  if (err.code === 11000) {
    return res.status(400).json({
      error: "Duplicate entry",
      field: Object.keys(err.keyPattern)[0],
    });
  }

  res.status(500).json({
    error: "Internal server error",
    message: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log("╔═══════════════════════════════════════════════════════════╗");
  console.log("║                                                           ║");
  console.log("║          🚀 RENTAX Backend Server - MongoDB v2.0          ║");
  console.log("║                                                           ║");
  console.log("╚══════════════════════════════════════════════════════════╝");
  console.log("");
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 API Base URL: http://localhost:${PORT}/api`);
  console.log("");
  console.log("🔒 Security Features:");
  console.log("   ✓ Helmet security headers");
  console.log("   ✓ CORS protection");
  console.log("   ✓ Gzip compression");
  console.log("   ✓ Rate limiting (100 req/15min)");
  console.log("   ✓ MongoDB injection prevention");
  console.log("   ✓ JWT authentication");
  console.log("");
  console.log("⚡ Performance:");
  console.log("   ✓ Connection pooling (min: 2, max: 10)");
  console.log("   ✓ Database indexing");
  console.log("   ✓ Query optimization");
  console.log("    Response compression");
  console.log("");
  console.log("🔐 Default Users:");
  console.log("   - Super Admin: superadmin@rentax.com / admin123");
  console.log("   - Manager: manager@rentax.com / manager123");
  console.log("   - Supervisor: supervisor@rentax.com / supervisor123");
  console.log("");
  console.log("📚 API Documentation:");
  console.log("   - Health Check: GET /health");
  console.log("   - Login: POST /api/auth/login");
  console.log("   - Users: GET /api/users");
  console.log("   - Clients: GET /api/clients");
  console.log("   - Onboarding: GET /api/onboarding");
  console.log("   - Departments: GET /api/departments");
  console.log("   - Settings: GET /api/settings");
  console.log("   - Audit Logs: GET /api/audit-logs");
  console.log("");
  console.log("🛡️  Production-ready with all optimizations enabled!");
  console.log("");
});

module.exports = app;
