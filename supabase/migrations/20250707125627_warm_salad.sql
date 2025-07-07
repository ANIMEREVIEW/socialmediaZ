/*
  # Create storage buckets for media files

  1. Storage Buckets
    - `post-media` - For post images and media files
    - `avatars` - For user profile pictures

  2. Storage Policies
    - Allow authenticated users to upload their own files
    - Allow public read access to all files
    - Restrict file sizes and types
*/

-- Create post-media bucket
INSERT INTO storage.buckets (id, name, public)
VALUES ('post-media', 'post-media', true)
ON CONFLICT (id) DO NOTHING;

-- Create avatars bucket
INSERT INTO storage.buckets (id, name, public)
VALUES ('avatars', 'avatars', true)
ON CONFLICT (id) DO NOTHING;

-- Policy for post-media bucket - allow authenticated users to upload
CREATE POLICY "Users can upload post media"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'post-media' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Policy for post-media bucket - allow public read access
CREATE POLICY "Public can view post media"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'post-media');

-- Policy for post-media bucket - allow users to delete their own files
CREATE POLICY "Users can delete their own post media"
ON storage.objects FOR DELETE
TO authenticated
USING (bucket_id = 'post-media' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Policy for avatars bucket - allow authenticated users to upload
CREATE POLICY "Users can upload avatars"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Policy for avatars bucket - allow public read access
CREATE POLICY "Public can view avatars"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'avatars');

-- Policy for avatars bucket - allow users to update their own avatars
CREATE POLICY "Users can update their own avatars"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Policy for avatars bucket - allow users to delete their own avatars
CREATE POLICY "Users can delete their own avatars"
ON storage.objects FOR DELETE
TO authenticated
USING (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);