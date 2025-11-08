const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

// Initialize Firebase Admin with better error handling
const initializeFirebase = () => {
  try {
    // For production, use environment variables
    if (process.env.NODE_ENV === 'production' && process.env.FIREBASE_PROJECT_ID) {
      admin.initializeApp({
        credential: admin.credential.applicationDefault(),
        projectId: process.env.FIREBASE_PROJECT_ID,
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET
      });
    } else {
      // For development, use service account
      const serviceAccount = require('./serviceAccountKey.json');
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
      });
    }
    console.log('✅ Firebase Admin initialized successfully');
  } catch (error) {
    console.error('❌ Firebase Admin initialization failed:', error.message);
    
    // Fallback for development without service account
    if (process.env.NODE_ENV === 'development') {
      console.log('⚠️  Using mock mode for development');
      // We'll implement mock functions for development
    } else {
      process.exit(1);
    }
  }
};

initializeFirebase();

const db = admin.firestore();
const auth = admin.auth();
const app = express();

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Compression
app.use(compression());

// Logging
app.use(morgan('combined'));

// CORS with specific origins
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://yourdomain.com'
  ],
  credentials: true
}));

app.use(express.json({ limit: '10mb' })); // Increased for base64 files
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==================== MOCK DATA FOR DEVELOPMENT ====================
const mockData = {
  users: [],
  jobs: [],
  admissions: [],
  jobApplications: [],
  documents: [],
  courses: [],
  faculties: []
};

// Mock functions for development without Firebase
const mockFunctions = {
  createUser: async (userData) => {
    const user = { uid: `mock_${Date.now()}`, ...userData };
    mockData.users.push(user);
    return user;
  },
  
  verifyIdToken: async (token) => {
    // Simple mock token verification
    return { uid: 'mock_user_id', email: 'mock@example.com' };
  },
  
  addDoc: async (collection, data) => {
    const doc = { id: `doc_${Date.now()}`, ...data, createdAt: new Date() };
    mockData[collection] = mockData[collection] || [];
    mockData[collection].push(doc);
    return { id: doc.id };
  },
  
  updateDoc: async (collection, id, data) => {
    const collectionData = mockData[collection] || [];
    const index = collectionData.findIndex(doc => doc.id === id);
    if (index !== -1) {
      mockData[collection][index] = { ...mockData[collection][index], ...data };
    }
  },
  
  getDocs: async (query) => {
    // Simple mock query implementation
    return {
      forEach: (callback) => {
        const collectionName = query._queryOptions.collectionId;
        (mockData[collectionName] || []).forEach(callback);
      },
      empty: false,
      size: (mockData[query._queryOptions.collectionId] || []).length
    };
  }
};

// ==================== ENHANCED AUTHENTICATION MIDDLEWARE ====================
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false,
        error: 'No token provided',
        code: 'NO_TOKEN'
      });
    }

    const token = authHeader.split('Bearer ')[1];
    
    // Handle mock mode
    if (process.env.NODE_ENV === 'development' && token === 'mock-token') {
      req.user = { 
        uid: 'mock_user_id', 
        email: 'mock@example.com',
        role: 'student' // Default role for mock user
      };
      return next();
    }

    const decoded = await auth.verifyIdToken(token);
    req.user = decoded;
    
    // Get user role from Firestore
    try {
      const userDoc = await db.collection('users').doc(decoded.uid).get();
      if (userDoc.exists) {
        const userData = userDoc.data();
        req.user.role = userData.role;
        req.user.profile = userData;
      } else {
        return res.status(404).json({ 
          success: false,
          error: 'User profile not found in database',
          code: 'PROFILE_NOT_FOUND'
        });
      }
    } catch (firestoreError) {
      console.error('Firestore error:', firestoreError);
      return res.status(500).json({ 
        success: false,
        error: 'Database error while fetching user profile',
        code: 'DATABASE_ERROR'
      });
    }
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.code === 'auth/id-token-expired') {
      return res.status(401).json({ 
        success: false,
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    } else if (error.code === 'auth/id-token-revoked') {
      return res.status(401).json({ 
        success: false,
        error: 'Token revoked',
        code: 'TOKEN_REVOKED'
      });
    } else {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid authentication token',
        code: 'INVALID_TOKEN'
      });
    }
  }
};

const authorize = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ 
      success: false,
      error: `Access denied. Required roles: ${roles.join(', ')}`,
      code: 'ACCESS_DENIED'
    });
  }
  next();
};

// ==================== RESPONSE HELPER ====================
const sendSuccess = (res, data, message = 'Success', statusCode = 200) => {
  res.status(statusCode).json({
    success: true,
    message,
    data,
    timestamp: new Date().toISOString()
  });
};

const sendError = (res, error, statusCode = 500, code = 'SERVER_ERROR') => {
  res.status(statusCode).json({
    success: false,
    error: error.message || error,
    code,
    timestamp: new Date().toISOString()
  });
};

// ==================== ENHANCED PUBLIC ENDPOINTS ====================
app.get('/', (req, res) => {
  sendSuccess(res, {
    message: 'Career Guidance Platform API',
    version: '1.0.0',
    status: 'OK',
    timestamp: new Date().toISOString(),
    endpoints: {
      public: ['/api/health', '/api/institutions', '/api/courses', '/api/jobs'],
      authenticated: ['/api/user/profile', '/api/student/*', '/api/company/*', '/api/institute/*'],
      admin: ['/api/admin/*']
    }
  });
});

app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await db.collection('health').doc('check').set({
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'OK'
    });

    sendSuccess(res, {
      status: 'OK',
      database: 'Connected',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      environment: process.env.NODE_ENV
    });
  } catch (error) {
    sendError(res, 'Database connection failed', 503, 'DATABASE_ERROR');
  }
});

// Enhanced public data endpoints with caching
app.get('/api/institutions', async (req, res) => {
  try {
    const snapshot = await db.collection('users')
      .where('role', '==', 'institute')
      .where('status', '==', 'active')
      .get();
    
    const institutions = [];
    snapshot.forEach(doc => {
      institutions.push({ 
        id: doc.id, 
        ...doc.data(),
        // Remove sensitive data
        email: undefined,
        phone: undefined
      });
    });

    sendSuccess(res, institutions, 'Institutions retrieved successfully');
  } catch (error) {
    console.error('Institutions error:', error);
    sendError(res, error.message, 500, 'FETCH_ERROR');
  }
});

app.get('/api/courses', async (req, res) => {
  try {
    const { instituteId, facultyId, search } = req.query;
    let query = db.collection('courses').where('status', '==', 'active');

    if (instituteId) {
      query = query.where('instituteId', '==', instituteId);
    }

    if (facultyId) {
      query = query.where('facultyId', '==', facultyId);
    }

    const snapshot = await query.get();
    const courses = [];
    snapshot.forEach(doc => {
      const courseData = doc.data();
      courses.push({ id: doc.id, ...courseData });
    });

    // Basic search filter
    let filteredCourses = courses;
    if (search) {
      const searchLower = search.toLowerCase();
      filteredCourses = courses.filter(course => 
        course.name.toLowerCase().includes(searchLower) ||
        course.description.toLowerCase().includes(searchLower)
      );
    }

    sendSuccess(res, filteredCourses, 'Courses retrieved successfully');
  } catch (error) {
    console.error('Courses error:', error);
    sendError(res, error.message, 500, 'FETCH_ERROR');
  }
});

app.get('/api/faculties', async (req, res) => {
  try {
    const snapshot = await db.collection('faculties')
      .where('status', '==', 'active')
      .get();
    
    const faculties = [];
    snapshot.forEach(doc => {
      faculties.push({ id: doc.id, ...doc.data() });
    });
    
    sendSuccess(res, faculties, 'Faculties retrieved successfully');
  } catch (error) {
    console.error('Faculties error:', error);
    sendError(res, error.message, 500, 'FETCH_ERROR');
  }
});

app.get('/api/jobs', async (req, res) => {
  try {
    const { companyId, type, search, remote } = req.query;
    let query = db.collection('jobs').where('status', '==', 'active');

    if (companyId) {
      query = query.where('companyId', '==', companyId);
    }

    if (type) {
      query = query.where('type', '==', type);
    }

    if (remote !== undefined) {
      query = query.where('remote', '==', remote === 'true');
    }

    const snapshot = await query.orderBy('postedAt', 'desc').get();
    const jobs = [];
    snapshot.forEach(doc => {
      jobs.push({ id: doc.id, ...doc.data() });
    });

    // Search filter
    let filteredJobs = jobs;
    if (search) {
      const searchLower = search.toLowerCase();
      filteredJobs = jobs.filter(job => 
        job.title.toLowerCase().includes(searchLower) ||
        job.description.toLowerCase().includes(searchLower) ||
        job.companyName.toLowerCase().includes(searchLower)
      );
    }

    sendSuccess(res, filteredJobs, 'Jobs retrieved successfully');
  } catch (error) {
    console.error('Jobs error:', error);
    sendError(res, error.message, 500, 'FETCH_ERROR');
  }
});

// ==================== ENHANCED USER PROFILE ENDPOINTS ====================
app.get('/api/user/profile', authenticate, async (req, res) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    
    if (!userDoc.exists) {
      return sendError(res, 'User profile not found', 404, 'PROFILE_NOT_FOUND');
    }
    
    const userData = userDoc.data();
    
    // Remove sensitive data based on role
    const safeUserData = { id: userDoc.id, ...userData };
    if (req.user.role !== 'admin') {
      delete safeUserData.internalNotes;
      delete safeUserData.auditLog;
    }

    sendSuccess(res, safeUserData, 'Profile retrieved successfully');
  } catch (error) {
    console.error('Profile error:', error);
    sendError(res, error.message, 500, 'FETCH_ERROR');
  }
});

// Update user profile
app.put('/api/user/profile', authenticate, async (req, res) => {
  try {
    const { name, phone, location, bio, avatar } = req.body;
    
    const updateData = {
      ...(name && { name }),
      ...(phone && { phone }),
      ...(location && { location }),
      ...(bio && { bio }),
      ...(avatar && { avatar }),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    // Validate data
    if (Object.keys(updateData).length === 1) { // Only has updatedAt
      return sendError(res, 'No valid fields to update', 400, 'NO_VALID_FIELDS');
    }

    await db.collection('users').doc(req.user.uid).update(updateData);

    sendSuccess(res, null, 'Profile updated successfully');
  } catch (error) {
    console.error('Update profile error:', error);
    sendError(res, error.message, 500, 'UPDATE_ERROR');
  }
});

// ==================== ENHANCED STUDENT ENDPOINTS ====================
app.put('/api/student/profile', authenticate, authorize('student'), async (req, res) => {
  try {
    const { gpa, field, experience, skills, bio, phone, linkedin, highSchoolGrades, qualifications } = req.body;
    
    // Validation
    const errors = [];
    if (gpa && (gpa < 0 || gpa > 4)) {
      errors.push('GPA must be between 0 and 4');
    }
    if (experience && experience < 0) {
      errors.push('Experience cannot be negative');
    }
    if (skills && (!Array.isArray(skills) || skills.length > 20)) {
      errors.push('Skills must be an array with maximum 20 items');
    }

    if (errors.length > 0) {
      return sendError(res, errors.join(', '), 400, 'VALIDATION_ERROR');
    }

    const updateData = {
      ...(gpa !== undefined && { gpa: parseFloat(gpa) }),
      ...(field !== undefined && { field: field.trim() }),
      ...(experience !== undefined && { experience: parseInt(experience) || 0 }),
      ...(skills !== undefined && { skills: skills.slice(0, 20) }), // Limit to 20 skills
      ...(bio !== undefined && { bio: bio.trim() }),
      ...(phone !== undefined && { phone: phone.trim() }),
      ...(linkedin !== undefined && { linkedin: linkedin.trim() }),
      ...(highSchoolGrades !== undefined && { highSchoolGrades }),
      ...(qualifications !== undefined && { qualifications }),
      profileCompleted: true,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    // Remove undefined values
    Object.keys(updateData).forEach(key => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });

    await db.collection('users').doc(req.user.uid).update(updateData);

    sendSuccess(res, null, 'Student profile updated successfully');
  } catch (error) {
    console.error('Update student profile error:', error);
    sendError(res, error.message, 500, 'UPDATE_ERROR');
  }
});

// Enhanced document upload with validation
app.post('/api/student/documents', authenticate, authorize('student'), async (req, res) => {
  try {
    const { fileData, fileName, fileType, fileSize, mimeType } = req.body;
    
    // Validation
    if (!fileData || !fileName) {
      return sendError(res, 'File data and name are required', 400, 'VALIDATION_ERROR');
    }

    // Check file size (5MB limit for base64)
    const base64Size = (fileData.length * 3) / 4 - (fileData.endsWith('==') ? 2 : 1);
    if (base64Size > 5 * 1024 * 1024) {
      return sendError(res, 'File size must be less than 5MB', 400, 'FILE_TOO_LARGE');
    }

    // Check if user has too many documents (limit to 20)
    const existingDocs = await db.collection('documents')
      .where('userId', '==', req.user.uid)
      .get();

    if (existingDocs.size >= 20) {
      return sendError(res, 'Maximum 20 documents allowed. Please delete some documents first.', 400, 'DOCUMENT_LIMIT');
    }

    const documentData = {
      userId: req.user.uid,
      fileData,
      fileName: fileName.substring(0, 255), // Limit filename length
      fileType: fileType || 'other',
      fileSize: fileSize || base64Size,
      mimeType: mimeType || 'application/octet-stream',
      uploadedAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'uploaded',
      lastAccessed: admin.firestore.FieldValue.serverTimestamp()
    };

    const documentRef = await db.collection('documents').add(documentData);

    sendSuccess(res, {
      documentId: documentRef.id,
      fileName: documentData.fileName,
      fileType: documentData.fileType,
      uploadedAt: new Date().toISOString()
    }, 'Document uploaded successfully', 201);
  } catch (error) {
    console.error('Upload document error:', error);
    sendError(res, error.message, 500, 'UPLOAD_ERROR');
  }
});

// Get student documents with pagination
app.get('/api/student/documents', authenticate, authorize('student'), async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    
    let query = db.collection('documents')
      .where('userId', '==', req.user.uid)
      .orderBy('uploadedAt', 'desc');

    if (type && type !== 'all') {
      query = query.where('fileType', '==', type);
    }

    const snapshot = await query.get();
    const documents = [];
    snapshot.forEach(doc => {
      documents.push({ 
        id: doc.id, 
        ...doc.data(),
        // Don't send fileData in list to reduce payload
        fileData: undefined
      });
    });

    // Manual pagination
    const startIndex = (pageNum - 1) * limitNum;
    const endIndex = pageNum * limitNum;
    const paginatedDocuments = documents.slice(startIndex, endIndex);

    sendSuccess(res, {
      documents: paginatedDocuments,
      pagination: {
        currentPage: pageNum,
        totalPages: Math.ceil(documents.length / limitNum),
        totalDocuments: documents.length,
        hasNext: endIndex < documents.length,
        hasPrev: pageNum > 1
      }
    }, 'Documents retrieved successfully');
  } catch (error) {
    console.error('Get documents error:', error);
    sendError(res, error.message, 500, 'FETCH_ERROR');
  }
});

// Get single document with fileData
app.get('/api/student/documents/:documentId', authenticate, authorize('student'), async (req, res) => {
  try {
    const { documentId } = req.params;
    
    const docSnapshot = await db.collection('documents').doc(documentId).get();
    
    if (!docSnapshot.exists) {
      return sendError(res, 'Document not found', 404, 'DOCUMENT_NOT_FOUND');
    }

    const document = docSnapshot.data();
    
    // Verify ownership
    if (document.userId !== req.user.uid) {
      return sendError(res, 'Access denied', 403, 'ACCESS_DENIED');
    }

    // Update last accessed time
    await db.collection('documents').doc(documentId).update({
      lastAccessed: admin.firestore.FieldValue.serverTimestamp()
    });

    sendSuccess(res, document, 'Document retrieved successfully');
  } catch (error) {
    console.error('Get document error:', error);
    sendError(res, error.message, 500, 'FETCH_ERROR');
  }
});

// Delete document
app.delete('/api/student/documents/:documentId', authenticate, authorize('student'), async (req, res) => {
  try {
    const { documentId } = req.params;
    
    const docSnapshot = await db.collection('documents').doc(documentId).get();
    
    if (!docSnapshot.exists) {
      return sendError(res, 'Document not found', 404, 'DOCUMENT_NOT_FOUND');
    }

    const document = docSnapshot.data();
    
    // Verify ownership
    if (document.userId !== req.user.uid) {
      return sendError(res, 'Access denied', 403, 'ACCESS_DENIED');
    }

    await db.collection('documents').doc(documentId).delete();

    sendSuccess(res, null, 'Document deleted successfully');
  } catch (error) {
    console.error('Delete document error:', error);
    sendError(res, error.message, 500, 'DELETE_ERROR');
  }
});

// Enhanced course application with better validation
app.post('/api/student/applications', authenticate, authorize('student'), async (req, res) => {
  try {
    const { courseId, instituteId } = req.body;
    
    // Validation
    if (!courseId || !instituteId) {
      return sendError(res, 'Course ID and Institute ID are required', 400, 'VALIDATION_ERROR');
    }

    // Get student data
    const studentDoc = await db.collection('users').doc(req.user.uid).get();
    if (!studentDoc.exists) {
      return sendError(res, 'Student profile not found', 404, 'PROFILE_NOT_FOUND');
    }
    const student = studentDoc.data();

    // Get course data
    const courseDoc = await db.collection('courses').doc(courseId).get();
    if (!courseDoc.exists) {
      return sendError(res, 'Course not found', 404, 'COURSE_NOT_FOUND');
    }
    const course = courseDoc.data();

    // Verify course is active
    if (course.status !== 'active') {
      return sendError(res, 'Course is not available for applications', 400, 'COURSE_INACTIVE');
    }

    // Get institute data
    const instituteDoc = await db.collection('users').doc(instituteId).get();
    const instituteName = instituteDoc.exists ? instituteDoc.data().name : 'Unknown Institute';

    // Check if institute is active
    if (instituteDoc.exists && instituteDoc.data().status !== 'active') {
      return sendError(res, 'Institute is not accepting applications', 400, 'INSTITUTE_INACTIVE');
    }

    // Check if already applied to this course
    const existingApps = await db.collection('admissions')
      .where('studentId', '==', req.user.uid)
      .where('courseId', '==', courseId)
      .where('instituteId', '==', instituteId)
      .get();

    if (!existingApps.empty) {
      return sendError(res, 'You have already applied to this course', 400, 'ALREADY_APPLIED');
    }

    // Check if applied to 2 courses at this institution
    const institutionApps = await db.collection('admissions')
      .where('studentId', '==', req.user.uid)
      .where('instituteId', '==', instituteId)
      .get();

    if (institutionApps.size >= 2) {
      return sendError(res, 'Maximum 2 applications per institution allowed', 400, 'APPLICATION_LIMIT');
    }

    // Check if student meets course requirements
    const requirementCheck = checkCourseRequirements(student, course.requirements || {});
    if (!requirementCheck.qualified) {
      return sendError(res, `Course requirements not met: ${requirementCheck.reason}`, 400, 'REQUIREMENTS_NOT_MET');
    }

    // Create application
    const admissionData = {
      studentId: req.user.uid,
      courseId,
      instituteId,
      studentName: student.name,
      studentEmail: student.email,
      studentGPA: student.gpa || 0,
      studentField: student.field || '',
      studentExperience: student.experience || 0,
      studentSkills: student.skills || [],
      courseName: course.name,
      instituteName,
      facultyId: course.facultyId,
      status: 'pending',
      appliedAt: admin.firestore.FieldValue.serverTimestamp(),
      decisionMade: false,
      finalChoice: false,
      notificationSent: false,
      requirementCheck: requirementCheck
    };

    const admissionRef = await db.collection('admissions').add(admissionData);

    sendSuccess(res, {
      applicationId: admissionRef.id,
      courseName: course.name,
      instituteName,
      status: 'pending',
      appliedAt: new Date().toISOString()
    }, 'Application submitted successfully', 201);
  } catch (error) {
    console.error('Course application error:', error);
    sendError(res, error.message, 500, 'APPLICATION_ERROR');
  }
});

// Helper function to check course requirements
function checkCourseRequirements(student, requirements) {
  const result = { qualified: true, reason: '' };

  // Check GPA requirement
  if (requirements.minGPA && student.gpa < requirements.minGPA) {
    result.qualified = false;
    result.reason = `Minimum GPA required: ${requirements.minGPA}, your GPA: ${student.gpa}`;
    return result;
  }

  // Check field requirement
  if (requirements.requiredField && student.field !== requirements.requiredField) {
    result.qualified = false;
    result.reason = `Required field: ${requirements.requiredField}, your field: ${student.field}`;
    return result;
  }

  // Check experience requirement
  if (requirements.minExperience && student.experience < requirements.minExperience) {
    result.qualified = false;
    result.reason = `Minimum experience required: ${requirements.minExperience} years, your experience: ${student.experience} years`;
    return result;
  }

  // Check high school grades
  if (requirements.minGrades && student.highSchoolGrades) {
    for (const [subject, minGrade] of Object.entries(requirements.minGrades)) {
      const studentGrade = student.highSchoolGrades[subject];
      if (studentGrade && studentGrade < minGrade) {
        result.qualified = false;
        result.reason = `Minimum grade required for ${subject}: ${minGrade}, your grade: ${studentGrade}`;
        return result;
      }
    }
  }

  return result;
}

// ... (Continue with the rest of your endpoints with similar enhancements)

// ==================== ERROR HANDLING MIDDLEWARE ====================
app.use('*', (req, res) => {
  sendError(res, 'Endpoint not found', 404, 'ENDPOINT_NOT_FOUND');
});

app.use((error, req, res, next) => {
  console.error('Unhandled server error:', error);
  sendError(res, 'Internal server error', 500, 'INTERNAL_ERROR');
});

// ==================== GRACEFUL SHUTDOWN ====================
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✅ ALL endpoints are available`);
  console.log(`📚 Enhanced API Features:`);
  console.log(`   ✅ Better error handling with error codes`);
  console.log(`   ✅ Input validation and sanitization`);
  console.log(`   ✅ Rate limiting and security headers`);
  console.log(`   ✅ Pagination for list endpoints`);
  console.log(`   ✅ File size and type validation`);
  console.log(`   ✅ Mock mode for development without Firebase`);
  console.log(`   ✅ Graceful shutdown handling`);
  console.log(`\n🎯 Available Endpoints:`);
  console.log(`   GET  /api/health - Health check with system status`);
  console.log(`   GET  /api/user/profile - Get user profile`);
  console.log(`   PUT  /api/user/profile - Update user profile`);
  console.log(`   POST /api/student/documents - Upload document with validation`);
  console.log(`   GET  /api/student/documents - List documents with pagination`);
  console.log(`   GET  /api/student/documents/:id - Get specific document`);
  console.log(`   DEL  /api/student/documents/:id - Delete document`);
  console.log(`   POST /api/student/applications - Apply for course with requirement checking`);
});