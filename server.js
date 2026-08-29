require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';

// ============ MIDDLEWARE ============
app.use(cors({
    origin: FRONTEND_URL,
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
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, WEBP, GIF allowed.'));
        }
    }
});

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

// --- CREATE NEWS (Protected) ---
app.post('/api/admin/news', authenticateJWT, upload.single('image'), async (req, res) => {
    try {
        const { title, description, date, category, video, register_link, location, link } = req.body;
        
        if (!title || !description || !date) {
            return res.status(400).json({ error: 'Title, description and date required' });
        }
        
        // Upload image if provided
        let imageUrl = null;
        if (req.file) {
            imageUrl = await uploadImageToStorage(req.file, 'news');
        }
        
        // Parse multiple_images if provided
        let multipleImages = [];
        if (req.body.multiple_images) {
            try {
                multipleImages = JSON.parse(req.body.multiple_images);
            } catch (e) {
                // If not JSON, treat as single string
                if (req.body.multiple_images) {
                    multipleImages = [req.body.multiple_images];
                }
            }
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
                multiple_images: multipleImages.length > 0 ? multipleImages : null,
                link: link || null,
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Create news error:', err);
        res.status(500).json({ error: err.message });
    }
});

// --- UPDATE NEWS (Protected) ---
app.put('/api/admin/news/:id', authenticateJWT, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, date, category, video, register_link, location, link } = req.body;
        
        // Get existing item to preserve image if no new one uploaded
        const { data: existing } = await supabaseAdmin
            .from('news_items')
            .select('image, multiple_images')
            .eq('id', id)
            .single();
        
        let imageUrl = existing?.image || null;
        if (req.file) {
            imageUrl = await uploadImageToStorage(req.file, 'news');
        }
        
        let multipleImages = existing?.multiple_images || [];
        if (req.body.multiple_images) {
            try {
                multipleImages = JSON.parse(req.body.multiple_images);
            } catch (e) {
                if (req.body.multiple_images) {
                    multipleImages = [req.body.multiple_images];
                }
            }
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
                multiple_images: multipleImages.length > 0 ? multipleImages : null,
                link: link || null
            })
            .eq('id', id)
            .select();
        
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        
        res.json({ success: true, data: data[0] });
    } catch (err) {
        console.error('Update news error:', err);
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
        .order('created_at', { ascending: false });
    
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
                status: 'replied',
                replied_at: new Date().toISOString()
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
// --- AUTO DELETE OLD QUERIES (Protected) ---
app.delete('/api/admin/queries/delete-old', authenticateJWT, async (req, res) => {
    try {
        // Calculate date 30 days ago
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        // Delete queries older than 30 days
        const { data, error } = await supabaseAdmin
            .from('queries')
            .delete()
            .lt('created_at', thirtyDaysAgo.toISOString());
        
        if (error) return res.status(500).json({ error: error.message });
        
        console.log('✅ Backend auto-deleted old queries');
        res.json({ success: true, message: 'Old queries deleted successfully' });
    } catch (err) {
        console.error('Auto-delete error:', err);
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

app.put('/api/admin/settings/password', authenticateJWT, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
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
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        // Hash new password
        const newHash = await bcrypt.hash(newPassword, 10);
        
        const { error } = await supabaseAdmin
            .from('admin_users')
            .update({ password_hash: newHash })
            .eq('id', req.user.id);
        
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true });
    } catch (err) {
        console.error('Update password error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ============ START SERVER ============
app.listen(PORT, () => {
    console.log(`🚀 Backend server running on port ${PORT}`);
    console.log(`📡 Frontend URL: ${FRONTEND_URL}`);
});