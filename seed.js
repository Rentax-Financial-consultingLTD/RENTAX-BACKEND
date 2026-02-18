/**
 * RENTAX Database Seed Script
 * Populates MongoDB with initial data for development and testing
 *
 * Usage: node seed.js
 */

require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/rentax";

// ============================================================================
// MONGOOSE SCHEMAS (Duplicated from server.js for seeding)
// ============================================================================

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
    role: { type: String, required: true },
    department: { type: String, required: true },
    status: { type: String, default: "active" },
    lastLogin: { type: Date },
  },
  { timestamps: true },
);

const clientSchema = new mongoose.Schema(
  {
    businessName: { type: String, required: true },
    contactPerson: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    package: { type: String, required: true },
    serviceType: { type: String, required: true },
    status: { type: String, default: "active" },
    onboardingStatus: { type: String, default: "active" },
    registrationDate: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now },
    mrr: { type: Number, default: 0 },
    complianceScore: { type: Number, default: 85 },
    businessSize: { type: String },
    industry: { type: String },
    tenantId: { type: String, unique: true },
  },
  { timestamps: true },
);

const onboardingApplicationSchema = new mongoose.Schema(
  {
    businessName: { type: String, required: true },
    contactPerson: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    selectedPackage: { type: String, required: true },
    serviceType: { type: String, required: true },
    businessSize: { type: String },
    industry: { type: String },
    status: { type: String, default: "pending" },
    submittedAt: { type: Date, default: Date.now },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    reviewedAt: { type: Date },
    approvalNotes: { type: String },
    rejectionReason: { type: String },
  },
  { timestamps: true },
);

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

const systemSettingsSchema = new mongoose.Schema(
  {
    settingKey: { type: String, required: true, unique: true },
    settingValue: { type: mongoose.Schema.Types.Mixed, required: true },
    category: { type: String },
    description: { type: String },
  },
  { timestamps: true },
);

const auditLogSchema = new mongoose.Schema(
  {
    entityType: { type: String, required: true },
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

// Models
const User = mongoose.model("User", userSchema);
const Client = mongoose.model("Client", clientSchema);
const OnboardingApplication = mongoose.model(
  "OnboardingApplication",
  onboardingApplicationSchema,
);
const Department = mongoose.model("Department", departmentSchema);
const SystemSettings = mongoose.model("SystemSettings", systemSettingsSchema);
const AuditLog = mongoose.model("AuditLog", auditLogSchema);

// ============================================================================
// SEED DATA
// ============================================================================

async function seedDatabase() {
  try {
    console.log("🌱 Starting database seeding...\n");

    // Connect to MongoDB
    await mongoose.connect(MONGODB_URI, {
      maxPoolSize: 10,
      minPoolSize: 2,
    });
    console.log("✅ Connected to MongoDB\n");

    // Clear existing data
    console.log("🗑️  Clearing existing data...");
    await Promise.all([
      User.deleteMany({}),
      Client.deleteMany({}),
      OnboardingApplication.deleteMany({}),
      Department.deleteMany({}),
      SystemSettings.deleteMany({}),
      AuditLog.deleteMany({}),
    ]);
    console.log("✅ Existing data cleared\n");

    // Seed Users
    console.log("👥 Seeding users...");
    const users = await User.insertMany([
      {
        email: "superadmin@rentax.com",
        password: await bcrypt.hash("admin123", 10),
        name: "John Doe",
        role: "super_admin",
        department: "compliance",
        status: "active",
        lastLogin: new Date(),
      },
      {
        email: "manager@rentax.com",
        password: await bcrypt.hash("manager123", 10),
        name: "Jane Smith",
        role: "operational_manager",
        department: "audit",
        status: "active",
        lastLogin: new Date(),
      },
      {
        email: "supervisor@rentax.com",
        password: await bcrypt.hash("supervisor123", 10),
        name: "Mike Wilson",
        role: "supervisor",
        department: "accounts",
        status: "active",
        lastLogin: new Date(),
      },
      {
        email: "hod@rentax.com",
        password: await bcrypt.hash("hod123", 10),
        name: "Sarah Johnson",
        role: "head_of_department",
        department: "tax",
        status: "active",
        lastLogin: new Date(),
      },
      {
        email: "staff@rentax.com",
        password: await bcrypt.hash("staff123", 10),
        name: "Tom Brown",
        role: "staff",
        department: "marketing",
        status: "active",
        lastLogin: new Date(),
      },
    ]);
    console.log(`✅ Created ${users.length} users\n`);

    // Seed Departments
    console.log("🏢 Seeding departments...");
    const departments = await Department.insertMany([
      {
        name: "Legal & Regulatory",
        code: "legal",
        description: "Legal compliance and regulatory oversight",
        headOfDepartment: users[3]._id,
        staffCount: 12,
        activeClients: 45,
        pendingTasks: 23,
        completedTasks: 156,
      },
      {
        name: "Tax & Compliance",
        code: "tax",
        description: "Tax planning and compliance services",
        headOfDepartment: users[3]._id,
        staffCount: 18,
        activeClients: 67,
        pendingTasks: 34,
        completedTasks: 289,
      },
      {
        name: "Accounting Department",
        code: "accounts",
        description: "Financial accounting and bookkeeping",
        headOfDepartment: users[2]._id,
        staffCount: 15,
        activeClients: 52,
        pendingTasks: 28,
        completedTasks: 234,
      },
      {
        name: "Audit Department",
        code: "audit",
        description: "Internal and external audit services",
        headOfDepartment: users[1]._id,
        staffCount: 10,
        activeClients: 38,
        pendingTasks: 19,
        completedTasks: 178,
      },
      {
        name: "Customer Care",
        code: "marketing",
        description: "Client relations and support",
        headOfDepartment: users[4]._id,
        staffCount: 8,
        activeClients: 156,
        pendingTasks: 45,
        completedTasks: 423,
      },
      {
        name: "Administration",
        code: "compliance",
        description: "General administration and operations",
        headOfDepartment: users[0]._id,
        staffCount: 6,
        activeClients: 0,
        pendingTasks: 12,
        completedTasks: 89,
      },
    ]);
    console.log(`✅ Created ${departments.length} departments\n`);

    // Seed Clients
    console.log("💼 Seeding clients...");
    const businessNames = [
      "Acme Corporation",
      "TechVision Ltd",
      "Global Imports Co",
      "Sunset Restaurant",
      "GreenLeaf Farms",
      "Urban Construction",
      "Digital Solutions Inc",
      "Premium Auto Parts",
      "Coast Shipping Ltd",
      "Mountain Coffee Co",
      "Elite Fashion House",
      "Smart Electronics",
      "Heritage Hotels",
      "Future Energy Systems",
      "Golden Harvest Agro",
      "Metro Transport",
      "Bright Star Education",
      "Omega Engineering",
      "Prime Real Estate",
      "Victory Sports Club",
    ];

    const clientsData = [];
    for (let i = 0; i < 156; i++) {
      const pkg = ["silver", "gold", "platinum"][i % 3];
      const serviceType = ["one_time", "annual"][Math.floor(Math.random() * 2)];
      const status =
        i < 140
          ? "active"
          : ["inactive", "suspended"][Math.floor(Math.random() * 2)];

      clientsData.push({
        businessName: `${businessNames[i % businessNames.length]} ${Math.floor(i / businessNames.length) + 1}`,
        contactPerson: `Contact Person ${i + 1}`,
        email: `client${i + 1}@business.com`,
        phone: `+255 ${Math.floor(Math.random() * 900 + 100)} ${Math.floor(Math.random() * 900000 + 100000)}`,
        package: pkg,
        serviceType,
        status,
        onboardingStatus: "active",
        registrationDate: new Date(2024, 0, 1 + (i % 365)),
        lastActivity: new Date(2024, 0, 1 + Math.floor(Math.random() * 365)),
        mrr: pkg === "silver" ? 50000 : pkg === "gold" ? 150000 : 300000,
        complianceScore: Math.floor(Math.random() * 30) + 70,
        businessSize: ["micro", "small", "medium", "large"][
          Math.floor(Math.random() * 4)
        ],
        industry: ["Technology", "Retail", "Manufacturing", "Services"][
          Math.floor(Math.random() * 4)
        ],
        tenantId: `tenant-${i + 1}`,
      });
    }
    const clients = await Client.insertMany(clientsData);
    console.log(`✅ Created ${clients.length} clients\n`);

    // Seed Onboarding Applications
    console.log("📝 Seeding onboarding applications...");
    const applicationsData = [];
    for (let i = 0; i < 20; i++) {
      const status =
        i < 8
          ? "pending"
          : ["under_review", "approved", "rejected"][
              Math.floor(Math.random() * 3)
            ];

      applicationsData.push({
        businessName: `New Business ${i + 1}`,
        contactPerson: `Owner ${i + 1}`,
        email: `newbusiness${i + 1}@email.com`,
        phone: `+255 ${Math.floor(Math.random() * 900 + 100)} ${Math.floor(Math.random() * 900000 + 100000)}`,
        selectedPackage: ["silver", "gold", "platinum"][
          Math.floor(Math.random() * 3)
        ],
        serviceType: ["one_time", "annual"][Math.floor(Math.random() * 2)],
        businessSize: ["micro", "small", "medium", "large"][
          Math.floor(Math.random() * 4)
        ],
        industry: ["Technology", "Retail", "Manufacturing", "Services"][
          Math.floor(Math.random() * 4)
        ],
        status,
        submittedAt: new Date(2024, 1, 1 + i),
        reviewedBy:
          status === "approved" || status === "rejected" ? users[0]._id : null,
        reviewedAt:
          status === "approved" || status === "rejected"
            ? new Date(2024, 1, 2 + i)
            : null,
        approvalNotes:
          status === "approved" ? "Application meets all requirements" : null,
        rejectionReason:
          status === "rejected" ? "Incomplete documentation" : null,
      });
    }
    const applications =
      await OnboardingApplication.insertMany(applicationsData);
    console.log(`✅ Created ${applications.length} onboarding applications\n`);

    // Seed System Settings
    console.log("⚙️  Seeding system settings...");
    const settings = await SystemSettings.insertMany([
      {
        settingKey: "packages",
        category: "packages",
        settingValue: [
          {
            name: "silver",
            displayName: "Silver",
            price: 50000,
            currency: "TZS",
            maxUsers: 3,
            maxStorage: 5,
            color: "#94a3b8",
            features: [
              {
                id: "basic_consultation",
                name: "Basic Consultation",
                enabled: true,
              },
              {
                id: "compliance_advisory",
                name: "Compliance Advisory",
                enabled: true,
              },
              { id: "document_upload", name: "Document Upload", enabled: true },
            ],
          },
          {
            name: "gold",
            displayName: "Gold",
            price: 150000,
            currency: "TZS",
            maxUsers: 10,
            maxStorage: 20,
            color: "#f59e0b",
            features: [
              { id: "all_silver", name: "All Silver Features", enabled: true },
              {
                id: "financial_management",
                name: "Financial Management",
                enabled: true,
              },
              { id: "task_requests", name: "Task Requests", enabled: true },
              {
                id: "periodic_reports",
                name: "Periodic Reports",
                enabled: true,
              },
            ],
          },
          {
            name: "platinum",
            displayName: "Platinum",
            price: 300000,
            currency: "TZS",
            maxUsers: 999,
            maxStorage: 100,
            color: "#a855f7",
            features: [
              { id: "all_gold", name: "All Gold Features", enabled: true },
              {
                id: "enterprise_oversight",
                name: "Full Enterprise Oversight",
                enabled: true,
              },
              {
                id: "strategic_advisory",
                name: "Strategic Advisory",
                enabled: true,
              },
              {
                id: "priority_support",
                name: "Priority Support",
                enabled: true,
              },
              { id: "api_access", name: "API Access", enabled: true },
            ],
          },
        ],
        description: "Package configurations",
      },
    ]);
    console.log(`✅ Created ${settings.length} system settings\n`);

    // Seed Audit Logs
    console.log("📊 Seeding audit logs...");
    const auditLogsData = [];
    const actions = [
      "task_created",
      "task_assigned",
      "task_status_changed",
      "task_completed",
      "client_approved",
      "client_rejected",
      "user_created",
      "user_role_changed",
      "sales_record_created",
      "expense_record_created",
      "pl_statement_generated",
    ];

    for (let i = 0; i < 100; i++) {
      const action = actions[Math.floor(Math.random() * actions.length)];
      const user = users[Math.floor(Math.random() * users.length)];
      const daysAgo = Math.floor(Math.random() * 30);

      auditLogsData.push({
        entityType: action.includes("task")
          ? "task"
          : action.includes("client")
            ? "client"
            : action.includes("user")
              ? "user"
              : "financial",
        entityId: `entity-${i + 1}`,
        action,
        performedBy: user._id,
        performedByName: user.name,
        performedByRole: user.role,
        timestamp: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000),
        changes: action.includes("changed")
          ? [{ field: "status", oldValue: "pending", newValue: "in_progress" }]
          : null,
        metadata: {
          department: user.department,
          tenantId:
            Math.random() > 0.5
              ? `tenant-${Math.floor(Math.random() * 5) + 1}`
              : null,
        },
      });
    }
    const auditLogs = await AuditLog.insertMany(auditLogsData);
    console.log(`✅ Created ${auditLogs.length} audit logs\n`);

    // Summary
    console.log(
      "╔═══════════════════════════════════════════════════════════╗",
    );
    console.log(
      "║                                                           ║",
    );
    console.log(
      "║              ✅ Database Seeding Complete!                ║",
    );
    console.log(
      "║                                                           ║",
    );
    console.log(
      "╚═══════════════════════════════════════════════════════════╝",
    );
    console.log("");
    console.log("📊 Summary:");
    console.log(`   - Users: ${users.length}`);
    console.log(`   - Clients: ${clients.length}`);
    console.log(`   - Onboarding Applications: ${applications.length}`);
    console.log(`   - Departments: ${departments.length}`);
    console.log(`   - System Settings: ${settings.length}`);
    console.log(`   - Audit Logs: ${auditLogs.length}`);
    console.log("");
    console.log("🔐 Login Credentials:");
    console.log("   - Super Admin: superadmin@rentax.com / admin123");
    console.log("   - Manager: manager@rentax.com / manager123");
    console.log("   - Supervisor: supervisor@rentax.com / supervisor123");
    console.log("   - HOD: hod@rentax.com / hod123");
    console.log("   - Staff: staff@rentax.com / staff123");
    console.log("");
    console.log("🚀 You can now start the server with: npm start");
    console.log("");
  } catch (error) {
    console.error("❌ Seeding error:", error);
  } finally {
    await mongoose.connection.close();
    console.log("👋 MongoDB connection closed");
    process.exit(0);
  }
}

// Run seed
seedDatabase();
