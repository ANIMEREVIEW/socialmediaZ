-- Fix RLS policies for posts table to work with auth.uid()
DROP POLICY IF EXISTS "Users can create posts" ON public.posts;
DROP POLICY IF EXISTS "Users can update their own posts" ON public.posts;

-- Create new RLS policies that use auth.uid() directly
CREATE POLICY "Users can create posts" 
ON public.posts 
FOR INSERT 
WITH CHECK (auth.uid()::text = user_id);

CREATE POLICY "Users can update their own posts" 
ON public.posts 
FOR UPDATE 
USING (auth.uid()::text = user_id);

-- Also fix other tables that use the same pattern
DROP POLICY IF EXISTS "Users can manage their own likes" ON public.likes;
CREATE POLICY "Users can manage their own likes" 
ON public.likes 
FOR ALL 
USING (auth.uid()::text = user_id);

DROP POLICY IF EXISTS "Users can manage their own retweets" ON public.retweets;
CREATE POLICY "Users can manage their own retweets" 
ON public.retweets 
FOR ALL 
USING (auth.uid()::text = user_id);

DROP POLICY IF EXISTS "Users can create comments" ON public.comments;
CREATE POLICY "Users can create comments" 
ON public.comments 
FOR INSERT 
WITH CHECK (auth.uid()::text = user_id);

DROP POLICY IF EXISTS "Users can update their own comments" ON public.comments;
CREATE POLICY "Users can update their own comments" 
ON public.comments 
FOR UPDATE 
USING (auth.uid()::text = user_id);

-- Enable realtime for posts table
ALTER TABLE public.posts REPLICA IDENTITY FULL;
ALTER publication supabase_realtime ADD TABLE public.posts;