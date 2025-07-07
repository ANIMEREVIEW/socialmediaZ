// Enhanced posts service with better query functions
import { supabase } from '@/integrations/supabase/client';

export interface PostWithEngagement {
  id: string;
  user_id: string;
  username: string;
  user_avatar?: string;
  content: string;
  post_type: string;
  media_url?: string;
  link_url?: string;
  link_title?: string;
  anime_id?: string;
  anime_title?: string;
  anime_image?: string;
  like_count: number;
  retweet_count: number;
  comment_count: number;
  created_at: string;
  original_post_id?: string;
  trending_score?: number;
  isLiked?: boolean;
  isRetweeted?: boolean;
}

export const postsService = {
  async getRecentPosts(limit: number = 50): Promise<PostWithEngagement[]> {
    const { data, error } = await supabase
      .from('posts')
      .select('*')
      .eq('status', 'approved')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;
    return data || [];
  },

  async getTrendingPosts(limit: number = 50): Promise<PostWithEngagement[]> {
    const { data, error } = await supabase
      .rpc('get_trending_posts', { limit_param: limit });

    if (error) throw error;
    return data || [];
  },

  async getFollowingPosts(userId: string, limit: number = 50): Promise<PostWithEngagement[]> {
    const { data, error } = await supabase
      .rpc('get_following_posts', { 
        user_id_param: userId, 
        limit_param: limit 
      });

    if (error) throw error;
    return data || [];
  },

  async getPostsWithUserEngagement(posts: PostWithEngagement[], userId: string): Promise<PostWithEngagement[]> {
    if (!posts.length) return posts;

    const postIds = posts.map(p => p.id);
    
    const [likesData, retweetsData] = await Promise.all([
      supabase
        .from('likes')
        .select('post_id')
        .eq('user_id', userId)
        .in('post_id', postIds),
      supabase
        .from('retweets')
        .select('post_id')
        .eq('user_id', userId)
        .in('post_id', postIds)
    ]);

    const likedPosts = new Set(likesData.data?.map(l => l.post_id) || []);
    const retweetedPosts = new Set(retweetsData.data?.map(r => r.post_id) || []);

    return posts.map(post => ({
      ...post,
      isLiked: likedPosts.has(post.id),
      isRetweeted: retweetedPosts.has(post.id)
    }));
  },

  async searchPosts(query: string, limit: number = 50): Promise<PostWithEngagement[]> {
    const { data, error } = await supabase
      .from('posts')
      .select('*')
      .eq('status', 'approved')
      .or(`content.ilike.%${query}%,anime_title.ilike.%${query}%,username.ilike.%${query}%`)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;
    return data || [];
  },

  async toggleLike(postId: string, userId: string): Promise<boolean> {
    // Check if already liked
    const { data: existingLike } = await supabase
      .from('likes')
      .select('id')
      .eq('user_id', userId)
      .eq('post_id', postId)
      .maybeSingle();

    if (existingLike) {
      // Unlike
      const { error } = await supabase
        .from('likes')
        .delete()
        .eq('user_id', userId)
        .eq('post_id', postId);
      
      if (error) throw error;
      return false;
    } else {
      // Like
      const { error } = await supabase
        .from('likes')
        .insert({ user_id: userId, post_id: postId });
      
      if (error) throw error;
      return true;
    }
  },

  async toggleRetweet(postId: string, userId: string): Promise<boolean> {
    // Check if already retweeted
    const { data: existingRetweet } = await supabase
      .from('retweets')
      .select('id')
      .eq('user_id', userId)
      .eq('post_id', postId)
      .maybeSingle();

    if (existingRetweet) {
      // Un-retweet
      const { error } = await supabase
        .from('retweets')
        .delete()
        .eq('user_id', userId)
        .eq('post_id', postId);
      
      if (error) throw error;
      return false;
    } else {
      // Retweet
      const { error } = await supabase
        .from('retweets')
        .insert({ user_id: userId, post_id: postId });
      
      if (error) throw error;
      return true;
    }
  }
};