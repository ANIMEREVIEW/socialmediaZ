-- Create storage buckets for media uploads
INSERT INTO storage.buckets (id, name, public) VALUES 
  ('avatars', 'avatars', true),
  ('post-media', 'post-media', true);

-- Create policies for avatar uploads
CREATE POLICY "Avatar images are publicly accessible" 
ON storage.objects 
FOR SELECT 
USING (bucket_id = 'avatars');

CREATE POLICY "Users can upload their own avatar" 
ON storage.objects 
FOR INSERT 
WITH CHECK (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can update their own avatar" 
ON storage.objects 
FOR UPDATE 
USING (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Create policies for post media uploads
CREATE POLICY "Post media is publicly accessible" 
ON storage.objects 
FOR SELECT 
USING (bucket_id = 'post-media');

CREATE POLICY "Users can upload post media" 
ON storage.objects 
FOR INSERT 
WITH CHECK (bucket_id = 'post-media' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Create enum for post status
CREATE TYPE post_status AS ENUM ('pending', 'approved', 'rejected');

-- Create enum for post type
CREATE TYPE post_type AS ENUM ('text', 'image', 'gif', 'link', 'retweet');

-- Update user_profiles table to include avatar and admin status
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS bio TEXT;
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS follower_count INTEGER DEFAULT 0;
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS following_count INTEGER DEFAULT 0;

-- Create posts table
CREATE TABLE IF NOT EXISTS posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  user_avatar TEXT,
  content TEXT NOT NULL,
  post_type post_type DEFAULT 'text',
  media_url TEXT,
  link_url TEXT,
  link_title TEXT,
  anime_id TEXT,
  anime_title TEXT,
  anime_image TEXT,
  status post_status DEFAULT 'pending',
  retweet_count INTEGER DEFAULT 0,
  like_count INTEGER DEFAULT 0,
  comment_count INTEGER DEFAULT 0,
  original_post_id UUID REFERENCES posts(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create comments table  
CREATE TABLE IF NOT EXISTS comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  user_avatar TEXT,
  content TEXT NOT NULL,
  like_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create likes table
CREATE TABLE IF NOT EXISTS likes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL,
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  comment_id UUID REFERENCES comments(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(user_id, post_id),
  UNIQUE(user_id, comment_id),
  CHECK ((post_id IS NOT NULL AND comment_id IS NULL) OR (post_id IS NULL AND comment_id IS NOT NULL))
);

-- Create retweets table
CREATE TABLE IF NOT EXISTS retweets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL,
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(user_id, post_id)
);

-- Create anime subscriptions table
CREATE TABLE IF NOT EXISTS anime_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL,
  anime_id TEXT NOT NULL,
  anime_title TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(user_id, anime_id)
);

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  is_read BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE likes ENABLE ROW LEVEL SECURITY;
ALTER TABLE retweets ENABLE ROW LEVEL SECURITY;
ALTER TABLE anime_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- RLS Policies for posts
CREATE POLICY "Anyone can view approved posts" ON posts
FOR SELECT USING (status = 'approved');

CREATE POLICY "Admins can view all posts" ON posts
FOR SELECT USING (
  current_setting('app.current_user_id', true) IN (
    SELECT user_id FROM user_profiles WHERE is_admin = true
  )
);

CREATE POLICY "Users can create posts" ON posts
FOR INSERT WITH CHECK (user_id = current_setting('app.current_user_id', true));

CREATE POLICY "Users can update their own posts" ON posts
FOR UPDATE USING (user_id = current_setting('app.current_user_id', true));

CREATE POLICY "Admins can update all posts" ON posts
FOR UPDATE USING (
  current_setting('app.current_user_id', true) IN (
    SELECT user_id FROM user_profiles WHERE is_admin = true
  )
);

-- RLS Policies for comments
CREATE POLICY "Anyone can view comments on approved posts" ON comments
FOR SELECT USING (
  post_id IN (SELECT id FROM posts WHERE status = 'approved')
);

CREATE POLICY "Users can create comments" ON comments
FOR INSERT WITH CHECK (user_id = current_setting('app.current_user_id', true));

CREATE POLICY "Users can update their own comments" ON comments
FOR UPDATE USING (user_id = current_setting('app.current_user_id', true));

-- RLS Policies for likes
CREATE POLICY "Anyone can view likes" ON likes FOR SELECT USING (true);
CREATE POLICY "Users can manage their own likes" ON likes
FOR ALL USING (user_id = current_setting('app.current_user_id', true));

-- RLS Policies for retweets
CREATE POLICY "Anyone can view retweets" ON retweets FOR SELECT USING (true);
CREATE POLICY "Users can manage their own retweets" ON retweets
FOR ALL USING (user_id = current_setting('app.current_user_id', true));

-- RLS Policies for anime subscriptions
CREATE POLICY "Users can manage their own subscriptions" ON anime_subscriptions
FOR ALL USING (user_id = current_setting('app.current_user_id', true));

-- RLS Policies for notifications
CREATE POLICY "Users can view their own notifications" ON notifications
FOR SELECT USING (user_id = current_setting('app.current_user_id', true));

CREATE POLICY "System can create notifications" ON notifications
FOR INSERT WITH CHECK (true);

-- Create function to update post counts
CREATE OR REPLACE FUNCTION update_post_counts()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF TG_TABLE_NAME = 'likes' AND NEW.post_id IS NOT NULL THEN
      UPDATE posts SET like_count = like_count + 1 WHERE id = NEW.post_id;
    ELSIF TG_TABLE_NAME = 'retweets' THEN
      UPDATE posts SET retweet_count = retweet_count + 1 WHERE id = NEW.post_id;
    ELSIF TG_TABLE_NAME = 'comments' THEN
      UPDATE posts SET comment_count = comment_count + 1 WHERE id = NEW.post_id;
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    IF TG_TABLE_NAME = 'likes' AND OLD.post_id IS NOT NULL THEN
      UPDATE posts SET like_count = like_count - 1 WHERE id = OLD.post_id;
    ELSIF TG_TABLE_NAME = 'retweets' THEN
      UPDATE posts SET retweet_count = retweet_count - 1 WHERE id = OLD.post_id;
    ELSIF TG_TABLE_NAME = 'comments' THEN
      UPDATE posts SET comment_count = comment_count - 1 WHERE id = OLD.post_id;
    END IF;
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updating counts
CREATE TRIGGER update_like_counts AFTER INSERT OR DELETE ON likes
FOR EACH ROW EXECUTE FUNCTION update_post_counts();

CREATE TRIGGER update_retweet_counts AFTER INSERT OR DELETE ON retweets
FOR EACH ROW EXECUTE FUNCTION update_post_counts();

CREATE TRIGGER update_comment_counts AFTER INSERT OR DELETE ON comments
FOR EACH ROW EXECUTE FUNCTION update_post_counts();

-- Enable realtime for all tables
ALTER TABLE posts REPLICA IDENTITY FULL;
ALTER TABLE comments REPLICA IDENTITY FULL;
ALTER TABLE likes REPLICA IDENTITY FULL;
ALTER TABLE retweets REPLICA IDENTITY FULL;
ALTER TABLE notifications REPLICA IDENTITY FULL;

-- Add tables to realtime publication
ALTER PUBLICATION supabase_realtime ADD TABLE posts;
ALTER PUBLICATION supabase_realtime ADD TABLE comments;
ALTER PUBLICATION supabase_realtime ADD TABLE likes;
ALTER PUBLICATION supabase_realtime ADD TABLE retweets;
ALTER PUBLICATION supabase_realtime ADD TABLE notifications;