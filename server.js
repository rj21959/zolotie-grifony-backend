require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://zolotiegrifony.ru';

// ============ CORS CONFIGURATION ============
// Allow multiple origins (frontend URLs)
const ALLOWED_ORIGINS = [
    'https://zolotiegrifony.ru',
    'https://www.zolotiegrifony.ru',
    'https://rj21959-zolotie-grifony-frontend-19cd.twc1.net',
    'https://zolotie-griffony.netlify.app'
];

// ============ MIDDLEWARE ============
app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, curl, etc.)
        if (!origin) return callback(null, true);
        
        if (ALLOWED_ORIGINS.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log('⚠️ CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ============ SUPABASE ADMIN CLIENT (SECURE - SERVER SIDE ONLY) ============
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

// ============ JWT AUTH MIDDLEWARE ============
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Unauthorized - No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// ============ FILE UPLOAD CONFIG ============
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 200 * 1024 * 1024 }, // 200MB for videos!
    fileFilter: (req, file, cb) => {
        const allowedImageTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        const allowedVideoTypes = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime'];
        
        if (allowedImageTypes.includes(file.mimetype) || allowedVideoTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    }
});
// Create a middleware for multiple images (using .array instead of .single)
const uploadMultiple = upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'multiple_images', maxCount: 10 }
]);

// ============ UPLOAD IMAGE TO SUPABASE STORAGE ============
async function uploadImageToStorage(file, folder = 'general') {
    if (!file) return null;
    
    try {
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${Date.now()}_${Math.random().toString(36).substring(2, 8)}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        
        const { data, error } = await supabaseAdmin
            .storage
            .from('images')
            .upload(filePath, file.buffer, {
                cacheControl: '3600',
                upsert: false,
                contentType: file.mimetype
            });
        
        if (error) throw error;
        
        const { data: urlData } = supabaseAdmin
            .storage
            .from('images')
            .getPublicUrl(filePath);
        
        return urlData.publicUrl;
    } catch (error) {
        console.error('Upload error:', error);
        return null;
    }
}

// ============ ROUTES ============

// --- Health Check ---
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// --- ADMIN LOGIN ---
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    try {
        // Get admin from Supabase
        const { data, error } = await supabaseAdmin
            .from('admin_users')
            .select('*')
            .eq('username', username)
            .single();
        
        if (error || !data) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Compare password
        const passwordMatch = await bcrypt.compare(password, data.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { id: data.id, username: data.username, role: data.role || 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );
        
        res.json({
            success: true,
            token: token,
            user: {
                id: data.id,
                username: data.username,
                email: data.email,
                role: data.role
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- CREATE INITIAL ADMIN (First time setup) ---
app.post('/api/admin/setup', async (req, res) => {
    const { username, password, email } = req.body;
    
    // Check if admin already exists
    const { data: existing } = await supabaseAdmin
        .from('admin_users')
        .select('id')
        .limit(1);
    
    if (existing && existing.length > 0) {
        return res.status(400).json({ error: 'Admin already exists' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    const { data, error } = await supabaseAdmin
        .from('admin_users')
        .insert([{
            username: username,
            password_hash: passwordHash,
            email: email,
            role: 'admin',
            created_at: new Date().toISOString()
        }])
        .select();
    
    if (error) {
        return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true, message: 'Admin created' });
});

// ========== ADD THIS NEW ROUTE HERE ==========
// --- REFRESH TOKEN ---
app.post('/api/admin/refresh-token', authenticateJWT, async (req, res) => {
    try {
        // Generate new token
        const newToken = jwt.sign(
            { id: req.user.id, username: req.user.username, role: req.user.role },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );
        
        res.json({ token: newToken });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- GET NEWS (Public) ---
app.get('/api/news', async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('news_items')
        .select('*')
        .order('created_at', { ascending: false });
    
    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data || []);
});

// --- GET EVENTS (Public) ---
app.get('/api/events', async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('news_items')
        .select('*')
        .eq('category', 'event')
        .order('date', { ascending: true });
    
    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data || []);
});

// --- CREATE NEWS (Protected) - UPDATED ---
app.post('/api/admin/news', authenticateJWT, uploadMultiple, async (req, res) => {
    try {
        const { title, description, date, category, video, register_link, location, link, multiple_images, image } = req.body;
        
        if (!title || !description || !date) {
            return res.status(400).json({ error: 'Title, description and date required' });
        }
        
        console.log('📝 Creating news:', { title, category, date });
        console.log('📎 Files received:', req.files ? Object.keys(req.files) : 'none');
        console.log('📎 Body:', { multiple_images: multiple_images ? 'present' : 'none', image: image ? 'present' : 'none' });
        
        // Upload MAIN image if provided
        let imageUrl = null;
        if (req.files && req.files.image && req.files.image.length > 0) {
            imageUrl = await uploadImageToStorage(req.files.image[0], 'news');
            console.log('✅ Main image uploaded:', imageUrl);
        } else if (image && typeof image === 'string' && image.startsWith('http')) {
            // Image is already a URL (existing image)
            imageUrl = image;
            console.log('✅ Using existing image URL:', imageUrl);
        }
        
        // Handle MULTIPLE images
        let multipleImages = [];
        
        // Check if we have files uploaded
        if (req.files && req.files.multiple_images && req.files.multiple_images.length > 0) {
            for (const file of req.files.multiple_images) {
                const url = await uploadImageToStorage(file, 'news_gallery');
                if (url) multipleImages.push(url);
            }
            console.log('✅ Uploaded multiple images from files:', multipleImages.length);
        } 
        // Check if multiple_images is sent as JSON string
        else if (multiple_images) {
            try {
                const parsed = JSON.parse(multiple_images);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    // Filter out any data URLs (these are already uploaded images)
                    multipleImages = parsed.filter(url => url && !url.startsWith('data:'));
                    console.log('✅ Multiple images from JSON (filtered):', multipleImages.length);
                }
            } catch (e) {
                console.log('⚠️ Could not parse multiple_images as JSON:', e.message);
            }
        }
        
        // If no images, set to null
        if (multipleImages.length === 0) {
            multipleImages = null;
        }
        
        const { data, error } = await supabaseAdmin
            .from('news_items')
            .insert([{
                title,
                description,
                date,
                category: category || 'news',
                image: imageUrl,
                video: video || null,
                register_link: register_link || null,
                location: location || null,
                multiple_images: multipleImages,
                link: link || null,
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) {
            console.error('❌ Supabase error:', error);
            return res.status(500).json({ error: error.message });
        }
        
        console.log('✅ News created:', data[0].id);
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('❌ Create news error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- UPDATE NEWS (Protected) - UPDATED ---
app.put('/api/admin/news/:id', authenticateJWT, uploadMultiple, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, date, category, video, register_link, location, link, multiple_images, image } = req.body;
        
        console.log('📝 Updating news:', id);
        
        // Get existing item
        const { data: existing, error: findError } = await supabaseAdmin
            .from('news_items')
            .select('image, multiple_images')
            .eq('id', id)
            .single();
        
        if (findError) {
            console.error('❌ Error finding news:', findError);
            return res.status(404).json({ error: 'News not found' });
        }
        
        // Handle main image
        let imageUrl = existing?.image || null;
        if (req.files && req.files.image && req.files.image.length > 0) {
            imageUrl = await uploadImageToStorage(req.files.image[0], 'news');
            console.log('✅ Main image updated');
        } else if (image && typeof image === 'string' && image.startsWith('http')) {
            imageUrl = image;
        }
        
        // Handle multiple images
        let multipleImages = [];
        
        if (req.files && req.files.multiple_images && req.files.multiple_images.length > 0) {
            for (const file of req.files.multiple_images) {
                const url = await uploadImageToStorage(file, 'news_gallery');
                if (url) multipleImages.push(url);
            }
            console.log('✅ Uploaded multiple images from files:', multipleImages.length);
        } else if (multiple_images) {
            try {
                const parsed = JSON.parse(multiple_images);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    multipleImages = parsed.filter(url => url && !url.startsWith('data:'));
                    console.log('✅ Multiple images from JSON:', multipleImages.length);
                }
            } catch (e) {
                console.log('⚠️ Could not parse multiple_images:', e.message);
            }
        }
        
        if (multipleImages.length === 0) {
            multipleImages = null;
        }
        
        const { data, error } = await supabaseAdmin
            .from('news_items')
            .update({
                title,
                description,
                date,
                category: category || 'news',
                image: imageUrl,
                video: video || null,
                register_link: register_link || null,
                location: location || null,
                multiple_images: multipleImages,
                link: link || null
            })
            .eq('id', id)
            .select();
        
        if (error) {
            console.error('❌ Supabase error:', error);
            return res.status(500).json({ error: error.message });
        }
        
        console.log('✅ News updated:', id);
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('❌ Update news error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- DELETE NEWS (Protected) ---
app.delete('/api/admin/news/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        
        const { error } = await supabaseAdmin
            .from('news_items')
            .delete()
            .eq('id', id);
        
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        
        res.json({ success: true });
    } catch (err) {
        console.error('Delete news error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- BRANCHES CRUD ---
app.get('/api/branches', async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('branches')
        .select('*')
        .order('date', { ascending: false }); // Sorts by your actual date column
    // OR if you are sure created_at exists: .order('created_at', { ascending: false });
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
});

app.post('/api/admin/branches', authenticateJWT, upload.single('image'), async (req, res) => {
    try {
        const { title, city, vk_link, description, date } = req.body;
        
        let imageUrl = null;
        if (req.file) {
            imageUrl = await uploadImageToStorage(req.file, 'branches');
        }
        
        const { data, error } = await supabaseAdmin
            .from('branches')
            .insert([{
                title,
                city: city || null,
                vk_link: vk_link || null,
                description: description || null,
                image: imageUrl,
                date: date || null,
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Create branch error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/branches/:id', authenticateJWT, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, city, vk_link, description, date } = req.body;
        
        const { data: existing } = await supabaseAdmin
            .from('branches')
            .select('image')
            .eq('id', id)
            .single();
        
        let imageUrl = existing?.image || null;
        if (req.file) {
            imageUrl = await uploadImageToStorage(req.file, 'branches');
        }
        
        const { data, error } = await supabaseAdmin
            .from('branches')
            .update({
                title,
                city: city || null,
                vk_link: vk_link || null,
                description: description || null,
                image: imageUrl,
                date: date || null
            })
            .eq('id', id)
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Update branch error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/branches/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabaseAdmin.from('branches').delete().eq('id', id);
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- AWARDS CRUD ---
app.get('/api/awards', async (req, res) => {
    const { data, error } = await supabaseAdmin.from('awards').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
});

app.post('/api/admin/awards', authenticateJWT, upload.single('image'), async (req, res) => {
    try {
        const { title, organization, year, description, link } = req.body;
        
        let imageUrl = null;
        if (req.file) {
            imageUrl = await uploadImageToStorage(req.file, 'awards');
        }
        
        const { data, error } = await supabaseAdmin
            .from('awards')
            .insert([{
                title,
                organization,
                year: parseInt(year),
                description: description || null,
                image: imageUrl,
                link: link || null,
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Create award error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/awards/:id', authenticateJWT, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, organization, year, description, link } = req.body;
        
        const { data: existing } = await supabaseAdmin
            .from('awards')
            .select('image')
            .eq('id', id)
            .single();
        
        let imageUrl = existing?.image || null;
        if (req.file) {
            imageUrl = await uploadImageToStorage(req.file, 'awards');
        }
        
        const { data, error } = await supabaseAdmin
            .from('awards')
            .update({
                title,
                organization,
                year: parseInt(year),
                description: description || null,
                image: imageUrl,
                link: link || null
            })
            .eq('id', id)
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Update award error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/awards/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabaseAdmin.from('awards').delete().eq('id', id);
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- MOMENTS CRUD ---
app.get('/api/moments', async (req, res) => {
    const { data, error } = await supabaseAdmin.from('moments').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
});

app.post('/api/admin/moments', authenticateJWT, async (req, res) => {
    try {
        const { title, description, videoUrl, link, thumbnail } = req.body;
        
        if (!title || !videoUrl) {
            return res.status(400).json({ error: 'Title and video URL required' });
        }
        
        const { data, error } = await supabaseAdmin
            .from('moments')
            .insert([{
                title,
                description: description || null,
                video_url: videoUrl,
                link: link || null,
                thumbnail: thumbnail || null,
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Create moment error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/moments/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, videoUrl, link, thumbnail } = req.body;
        
        const { data, error } = await supabaseAdmin
            .from('moments')
            .update({
                title,
                description: description || null,
                video_url: videoUrl,
                link: link || null,
                thumbnail: thumbnail || null
            })
            .eq('id', id)
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Update moment error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/moments/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabaseAdmin.from('moments').delete().eq('id', id);
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- QUERIES (Contact form submissions) ---
app.get('/api/admin/queries', authenticateJWT, async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('queries')
        .select('*')
        .order('created_at', { ascending: false });
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
});

app.post('/api/queries', async (req, res) => {
    try {
        const { name, email, message } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'All fields required' });
        }
        
        const { data, error } = await supabaseAdmin
            .from('queries')
            .insert([{
                name,
                email,
                message,
                status: 'pending',
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Create query error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/queries/:id/reply', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { reply } = req.body;
        
        const { data, error } = await supabaseAdmin
            .from('queries')
            .update({
                admin_reply: reply,
                status: 'replied'
            })
            .eq('id', id)
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Reply query error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- DELETE OLD QUERIES (Protected) ---
app.delete('/api/admin/queries/delete-old', async (req, res) => { // REMOVED authenticateJWT
    try {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        console.log("🚨 SERVER RECEIVED REQUEST, DELETING OLD QUERIES...");

        const { data, error } = await supabaseAdmin
            .from('queries')
            .delete()
            .not('created_at', 'is', null)
            .lt('created_at', thirtyDaysAgo.toISOString());

        if (error) {
            console.log("Auto-delete error (ignored):", error.message);
            return res.json({ success: true }); // Always send 200
        }

        console.log("✅ DELETED OLD QUERIES:", data?.length);
        res.json({ success: true });
    } catch (err) {
        console.log("Auto-delete catch (ignored):", err.message);
        res.json({ success: true }); // Always send 200
    }
});

// --- DELETE SINGLE QUERY (Protected) ---
// Note: This must come AFTER the delete-old route so Node.js doesn't confuse "delete-old" with an ID
app.delete('/api/admin/queries/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabaseAdmin.from('queries').delete().eq('id', id);
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- THEME SETTINGS ---
app.get('/api/theme', async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('site_settings')
        .select('theme_data, active_theme')
        .eq('id', 1)
        .single();
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || { theme_data: null });
});

app.put('/api/admin/theme', authenticateJWT, async (req, res) => {
    try {
        const { themeData } = req.body;
        
        const { data, error } = await supabaseAdmin
            .from('site_settings')
            .update({
                active_theme: themeData.festivalId || 'custom',
                theme_data: themeData,
                updated_at: new Date().toISOString()
            })
            .eq('id', 1)
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Update theme error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- HERO VIDEO ---
app.get('/api/hero-video', async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('hero_videos')
        .select('*')
        .eq('is_active', true)
        .order('uploaded_at', { ascending: false })
        .limit(1);
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data?.[0] || { video_url: 'videos/hero-bg.mp4' });
});

app.post('/api/admin/hero-video', authenticateJWT, upload.single('video'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No video file provided' });
        }
        
        // Upload to Supabase Storage
        const fileExt = req.file.originalname.split('.').pop();
        const fileName = `hero_${Date.now()}.${fileExt}`;
        const filePath = `hero/${fileName}`;
        
        const { error: uploadError } = await supabaseAdmin
            .storage
            .from('videos')
            .upload(filePath, req.file.buffer, {
                cacheControl: '3600',
                upsert: true,
                contentType: req.file.mimetype
            });
        
        if (uploadError) {
            return res.status(500).json({ error: uploadError.message });
        }
        
        const { data: urlData } = supabaseAdmin
            .storage
            .from('videos')
            .getPublicUrl(filePath);
        
        const videoUrl = urlData.publicUrl;
        
        // Deactivate old videos
        await supabaseAdmin
            .from('hero_videos')
            .update({ is_active: false })
            .neq('id', 0);
        
        // Insert new video
        const { data, error } = await supabaseAdmin
            .from('hero_videos')
            .insert([{
                video_url: videoUrl,
                is_active: true,
                uploaded_at: new Date().toISOString()
            }])
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Upload hero video error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/hero-video', authenticateJWT, async (req, res) => {
    try {
        await supabaseAdmin
            .from('hero_videos')
            .update({ is_active: false })
            .neq('id', 0);
        
        const { data, error } = await supabaseAdmin
            .from('hero_videos')
            .insert([{
                video_url: 'videos/hero-bg.mp4',
                is_active: true,
                uploaded_at: new Date().toISOString()
            }])
            .select();
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        console.error('Reset hero video error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- ADMIN SETTINGS ---
app.get('/api/admin/settings', authenticateJWT, async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('admin_users')
        .select('id, username, email, role')
        .eq('id', req.user.id)
        .single();
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// --- UPDATE PASSWORD (Protected) - REPLACES OLD PASSWORD HASH ---
app.put('/api/admin/settings/password', authenticateJWT, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Both current and new passwords required' });
        }

        // Get current user
        const { data: user } = await supabaseAdmin
            .from('admin_users')
            .select('password_hash')
            .eq('id', req.user.id)
            .single();
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        // Verify current password
        const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Текущий пароль неверен' });
        }
        
        // Hash new password
        const newHash = await bcrypt.hash(newPassword, 10);
        
        const { error } = await supabaseAdmin
            .from('admin_users')
            .update({ password_hash: newHash }) // Updates ONLY the hash column
            .eq('id', req.user.id);
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        console.error('Update password error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- UPDATE USERNAME (Protected) ---
app.put('/api/admin/settings/username', authenticateJWT, async (req, res) => {
    try {
        const { newUsername } = req.body;
        
        if (!newUsername) return res.status(400).json({ error: 'New username required' });

        const { data: existing } = await supabaseAdmin
            .from('admin_users')
            .select('id')
            .eq('username', newUsername)
            .maybeSingle();

        if (existing) return res.status(400).json({ error: 'Этот логин уже занят' });

        const { error } = await supabaseAdmin
            .from('admin_users')
            .update({ username: newUsername })
            .eq('id', req.user.id);
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- RESET PASSWORD BY EMAIL (No Auth) ---
app.post('/api/admin/setup-reset-by-email', async (req, res) => {
    try {
        const { email, newPassword, newUsername } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ error: 'Email and new password required' });
        }

        console.log('🔄 Reset by email');

        // Find user by EMAIL
        const { data: user, error: findError } = await supabaseAdmin
            .from('admin_users')
            .select('id, username, email')
            .eq('email', email)
            .single();

        if (findError || !user) {
            console.error('❌ User not found by email');
            return res.status(404).json({ error: 'Пользователь с таким email не найден' });
        }

        console.log('✅ User found:', user.username);

        // Hash new password
        const newHash = await bcrypt.hash(newPassword, 10);

        // Update password (and optionally username)
        const updateData = { password_hash: newHash };
        
        if (newUsername && newUsername.trim() !== '') {
            // Check if username is taken
            const { data: existing } = await supabaseAdmin
                .from('admin_users')
                .select('id')
                .eq('username', newUsername)
                .maybeSingle();
            
            if (existing && existing.id !== user.id) {
                return res.status(400).json({ error: 'Этот логин уже занят' });
            }
            updateData.username = newUsername;
        }

        // Update user
        const { error: updateError } = await supabaseAdmin
            .from('admin_users')
            .update(updateData)
            .eq('id', user.id);

        if (updateError) {
            console.error('❌ Update error:', updateError);
            return res.status(500).json({ error: updateError.message });
        }

        const finalUsername = updateData.username || user.username;
        console.log('✅ Reset successful for:', finalUsername);
        
        res.json({ 
            success: true,
            username: finalUsername
        });
        
    } catch (err) {
        console.error('❌ Reset error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- SITE STATS (Public) ---
app.get('/api/stats', async (req, res) => {
    const { data, error } = await supabaseAdmin
        .from('site_stats')
        .select('*')
        .eq('id', 1)
        .single();
    
    if (error) return res.status(500).json({ error: error.message });
    
    // Return the defaults if no row exists
    res.json(data || { active_volunteers: 150, completed_projects: 50, help_provided: 5000 });
});

// --- UPDATE SITE STATS (Protected) ---
app.put('/api/admin/stats', authenticateJWT, async (req, res) => {
    try {
        const { active_volunteers, completed_projects, help_provided } = req.body;

        const { data, error } = await supabaseAdmin
            .from('site_stats')
            .update({
                active_volunteers: parseInt(active_volunteers),
                completed_projects: parseInt(completed_projects),
                help_provided: parseInt(help_provided),
                updated_at: new Date().toISOString()
            })
            .eq('id', 1)
            .select();

        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, data: data[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ARCHIVE QUERY (Protected) ---
app.put('/api/admin/queries/:id/archive', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Get current status before archiving
        const { data: existing, error: findError } = await supabaseAdmin
            .from('queries')
            .select('status')
            .eq('id', id)
            .single();
        
        if (findError) {
            return res.status(500).json({ error: findError.message });
        }
        
        console.log('📦 Archiving query:', id, 'Previous status:', existing.status);
        
        const { data, error } = await supabaseAdmin
            .from('queries')
            .update({ 
                status: 'archived'
            })
            .eq('id', id)
            .select();
        
        if (error) {
            console.error('Archive query error:', error);
            return res.status(500).json({ error: error.message });
        }
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Archive query error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- UNARCHIVE QUERY (Protected) ---
app.put('/api/admin/queries/:id/unarchive', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        
        // FIRST: Get the current query to check if it has a reply
        const { data: existing, error: findError } = await supabaseAdmin
            .from('queries')
            .select('admin_reply')
            .eq('id', id)
            .single();
        
        if (findError) {
            return res.status(500).json({ error: findError.message });
        }
        
        // Determine the correct status
        // If it has a reply, set to 'replied', otherwise 'pending'
        const newStatus = (existing.admin_reply && existing.admin_reply.trim() !== '') 
            ? 'replied' 
            : 'pending';
        
        console.log('📤 Unarchiving query:', id, 'Status will be:', newStatus);
        
        const { data, error } = await supabaseAdmin
            .from('queries')
            .update({ 
                status: newStatus  // ← Set correct status based on whether it has a reply
            })
            .eq('id', id)
            .select();
        
        if (error) {
            console.error('Unarchive query error:', error);
            return res.status(500).json({ error: error.message });
        }
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Unarchive query error:', err);
        res.status(500).json({ error: err.message });
    }
});
// ============ GLOBAL ERROR HANDLER ============
app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    
    // Multer file size error
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File is too large. Max size is 200MB.' });
    }
    
    // Multer file type error
    if (err.message === 'Invalid file type') {
        return res.status(400).json({ error: 'Invalid file type. Only images and videos allowed.' });
    }
    
    // Any other error
    res.status(500).json({ error: err.message || 'Internal Server Error' });
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Backend server running on port ${PORT}`);
    console.log(`📡 Frontend URL: ${FRONTEND_URL}`);
});