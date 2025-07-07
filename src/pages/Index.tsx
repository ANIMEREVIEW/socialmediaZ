import { useEffect, useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { PostCard } from '@/components/PostCard';
import { CreatePost } from '@/components/CreatePost';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Bell, Search, Settings, Users, TrendingUp, Clock, Heart, Loader2 } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Link, useNavigate } from 'react-router-dom';
import { ProfileDropdown } from '@/components/ProfileDropdown';
import { postsService, PostWithEngagement } from '@/lib/posts';
import { supabase } from '@/integrations/supabase/client';

const Index = () => {
  const { user, loading, signOut, isAdmin } = useAuth();
  const [posts, setPosts] = useState<PostWithEngagement[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filteredPosts, setFilteredPosts] = useState<PostWithEngagement[]>([]);
  const [activeTab, setActiveTab] = useState('recent');
  const [notifications, setNotifications] = useState<any[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isLoadingPosts, setIsLoadingPosts] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user) {
      fetchPosts();
      fetchNotifications();
      setupRealtimeSubscription();
    }
  }, [user, activeTab]);

  useEffect(() => {
    if (searchQuery.trim()) {
      handleSearch();
    } else {
      setFilteredPosts(posts);
    }
  }, [searchQuery, posts]);

  const fetchPosts = async () => {
    if (!user) return;
    
    setIsLoadingPosts(true);
    try {
      let postsData: PostWithEngagement[] = [];

      // Set user context for RLS
      await supabase.rpc('set_config', { 
        setting_name: 'app.current_user_id', 
        setting_value: user.id 
      });

      switch (activeTab) {
        case 'trending':
          postsData = await postsService.getTrendingPosts(50);
          break;
        case 'following':
          postsData = await postsService.getFollowingPosts(user.id, 50);
          break;
        default:
          postsData = await postsService.getRecentPosts(50);
      }

      // Add user engagement data
      const postsWithEngagement = await postsService.getPostsWithUserEngagement(postsData, user.id);
      setPosts(postsWithEngagement);
    } catch (error) {
      console.error('Error fetching posts:', error);
      toast({ title: "Error", description: "Failed to load posts", variant: "destructive" });
    } finally {
      setIsLoadingPosts(false);
    }
  };

  const handleSearch = async () => {
    if (!user || !searchQuery.trim()) return;

    try {
      const searchResults = await postsService.searchPosts(searchQuery.trim());
      const resultsWithEngagement = await postsService.getPostsWithUserEngagement(searchResults, user.id);
      setFilteredPosts(resultsWithEngagement);
    } catch (error) {
      console.error('Error searching posts:', error);
      toast({ title: "Error", description: "Search failed", variant: "destructive" });
    }
  };

  const fetchNotifications = async () => {
    if (!user) return;

    try {
      const { data, error } = await supabase
        .from('notifications')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) {
        console.error('Error fetching notifications:', error);
        return;
      }

      setNotifications(data || []);
      setUnreadCount(data?.filter(n => !n.is_read).length || 0);
    } catch (error) {
      console.error('Error fetching notifications:', error);
    }
  };

  const setupRealtimeSubscription = () => {
    if (!user) return;

    const channel = supabase
      .channel('posts-changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'posts', filter: 'status=eq.approved' },
        () => {
          fetchPosts();
        }
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'likes' },
        () => {
          fetchPosts();
        }
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'retweets' },
        () => {
          fetchPosts();
        }
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'comments' },
        () => {
          fetchPosts();
        }
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'notifications', filter: `user_id=eq.${user.id}` },
        () => {
          fetchNotifications();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  };

  const handleSignOut = async () => {
    try {
      await signOut();
      navigate('/auth');
    } catch (error) {
      console.error('Sign out error:', error);
    }
  };

  const markNotificationsAsRead = async () => {
    if (!user || unreadCount === 0) return;

    try {
      await supabase
        .from('notifications')
        .update({ is_read: true })
        .eq('user_id', user.id)
        .eq('is_read', false);

      setUnreadCount(0);
      fetchNotifications();
    } catch (error) {
      console.error('Error marking notifications as read:', error);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-12 w-12 animate-spin mx-auto mb-4" />
          <p className="text-muted-foreground">Loading AnimeZ...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
          <p className="text-muted-foreground">Redirecting to login...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md">
        <div className="max-w-4xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h1 className="text-2xl font-bold bg-gradient-to-r from-primary to-purple-400 bg-clip-text text-transparent">
              AnimeZ
            </h1>
            {isAdmin && (
              <Badge variant="secondary" className="bg-gradient-to-r from-yellow-500/20 to-orange-500/20 text-yellow-300 border-yellow-500/30">
                <Users className="mr-1 h-3 w-3" />
                Admin
              </Badge>
            )}
          </div>

          <div className="flex-1 max-w-md mx-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
              <Input
                placeholder="Search posts, anime, users..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-muted/50"
              />
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <Button 
              variant="ghost" 
              size="sm" 
              className="relative"
              onClick={markNotificationsAsRead}
            >
              <Bell className="h-5 w-5" />
              {unreadCount > 0 && (
                <Badge 
                  variant="destructive" 
                  className="absolute -top-1 -right-1 h-5 w-5 p-0 text-xs flex items-center justify-center"
                >
                  {unreadCount > 9 ? '9+' : unreadCount}
                </Badge>
              )}
            </Button>
            
            {isAdmin && (
              <Button variant="ghost" size="sm" asChild>
                <Link to="/admin">
                  <Settings className="h-5 w-5" />
                </Link>
              </Button>
            )}

            <ProfileDropdown onSignOut={handleSignOut} />
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-2xl mx-auto px-4 py-6 space-y-6">
        <CreatePost onPostCreated={fetchPosts} />
        
        {/* Feed tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="recent" className="flex items-center space-x-2">
              <Clock className="h-4 w-4" />
              <span>Recent</span>
            </TabsTrigger>
            <TabsTrigger value="trending" className="flex items-center space-x-2">
              <TrendingUp className="h-4 w-4" />
              <span>Trending</span>
            </TabsTrigger>
            <TabsTrigger value="following" className="flex items-center space-x-2">
              <Heart className="h-4 w-4" />
              <span>Following</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab} className="space-y-4 mt-6">
            {isLoadingPosts ? (
              <div className="text-center py-12">
                <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
                <p className="text-muted-foreground">Loading posts...</p>
              </div>
            ) : filteredPosts.length === 0 ? (
              <div className="text-center py-12">
                <p className="text-muted-foreground">
                  {searchQuery ? 'No posts found matching your search.' : 
                   activeTab === 'following' ? 'Follow some users to see their posts here!' :
                   'No posts yet. Be the first to post!'}
                </p>
              </div>
            ) : (
              filteredPosts.map((post) => (
                <PostCard key={post.id} post={post} onUpdate={fetchPosts} />
              ))
            )}
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default Index;