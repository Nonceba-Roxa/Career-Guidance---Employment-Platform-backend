/**
 * seed.js — Creates only Firebase Auth admin users and Firestore profiles
 */
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const auth = admin.auth();
const db = admin.firestore();

// Utility function
async function safeSet(collection, docId, data) {
  const ref = db.collection(collection).doc(docId);
  await ref.set(data);
  console.log(`✅ Created ${collection}/${docId}`);
}

// Helper to create auth + Firestore user
async function createUserWithProfile({ email, password, role, ...rest }) {
  let userRecord;
  try {
    userRecord = await auth.createUser({ email, password });
    console.log(`👤 Created Auth user: ${email}`);
  } catch (err) {
    if (err.code === "auth/email-already-exists") {
      userRecord = await auth.getUserByEmail(email);
      console.log(`⚠️ Auth user already exists: ${email}`);
    } else {
      throw err;
    }
  }

  const userData = { 
    uid: userRecord.uid,
    email, 
    role, 
    ...rest,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    status: 'active'
  };

  await safeSet("users", userRecord.uid, userData);
  return userRecord.uid;
}

(async () => {
  try {
    console.log("🚀 Seeding Admin Users Only...");

    // Clean only users collection (keep other data if any)
    console.log("🗑️ Clearing existing users...");
    const usersSnap = await db.collection("users").get();
    const batch = db.batch();
    usersSnap.forEach(doc => batch.delete(doc.ref));
    await batch.commit();

    // Create 3 admin users in Firebase Auth + Firestore
    const admin1Id = await createUserWithProfile({
      email: "admin1@careerhub.com",
      password: "Admin123!",
      role: "admin",
      name: "System Admin 1"
    });

    const admin2Id = await createUserWithProfile({
      email: "admin2@careerhub.com",
      password: "Admin123!",
      role: "admin",
      name: "System Admin 2"
    });

    const admin3Id = await createUserWithProfile({
      email: "admin3@careerhub.com",
      password: "Admin123!",
      role: "admin",
      name: "System Admin 3"
    });

    console.log("\n📋 Admin Users Created:");
    console.log("1. admin1@careerhub.com / Admin123!");
    console.log("2. admin2@careerhub.com / Admin123!");
    console.log("3. admin3@careerhub.com / Admin123!");
    console.log("\n🔐 All admins use the same password: Admin123!");

    console.log("✅ Admin seeding complete!");
    process.exit(0);
  } catch (err) {
    console.error("❌ Seeding failed:", err);
    process.exit(1);
  }
})();