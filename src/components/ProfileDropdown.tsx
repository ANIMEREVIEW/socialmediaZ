import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { User, Settings, LogOut, Upload, Shield, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { supabase } from '@/integrations/supabase/client';
import { toast } from '@/hooks/use-toast';

interface ProfileDropdownProps {
  onSignOut: () => void;
}

export const ProfileDropdown = ({ onSignOut }: ProfileDropdownProps) => {
  const { user } = useAuth();
  const [showProfileDialog, setShowProfileDialog] = useState(false);
  const [showPasswordDialog, setShowPasswordDialog] = useState(false);
  const [username, setUsername] = useState(user?.profile?.username || '');
  const [bio, setBio] = useState(user?.profile?.bio || '');
  const [avatarFile, setAvatarFile] = useState<File | null>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [adminCode, setAdminCode] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      toast({ title: "Error", description: "Image size must be less than 5MB", variant: "destructive" });
      return;
    }

    if (!file.type.startsWith('image/')) {
      toast({ title: "Error", description: "Only image files are allowed", variant: "destructive" });
      return;
    }

    setAvatarFile(file);
    const reader = new FileReader();
    reader.onload = (e) => {
      setAvatarPreview(e.target?.result as string);
    };
    reader.readAsDataURL(file);
  };

  const uploadAvatar = async (file: File, userId: string): Promise<string | null> => {
    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${userId}.${fileExt}`;
      const filePath = `avatars/${fileName}`;

      // Remove existing avatar if it exists
      await supabase.storage
        .from('avatars')
        .remove([filePath]);

      const { error: uploadError } = await supabase.storage
        .from('avatars')
        .upload(filePath, file);

      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = supabase.storage
        .from('avatars')
        .getPublicUrl(filePath);

      return publicUrl;
    } catch (error) {
      console.error('Error uploading avatar:', error);
      return null;
    }
  };

  const handleUpdateProfile = async () => {
    if (!user) return;

    setIsUpdating(true);
    try {
      let avatarUrl = user.profile?.avatar_url;

      if (avatarFile) {
        const uploadedUrl = await uploadAvatar(avatarFile, user.id);
        if (uploadedUrl) {
          avatarUrl = uploadedUrl;
        }
      }

      const { data, error } = await supabase
        .from('user_profiles')
        .update({
          username: username.trim(),
          bio: bio.trim(),
          avatar_url: avatarUrl
        })
        .eq('user_id', user.id)
        .select()
        .single();

      if (error) {
        console.error('Profile update error:', error);
        throw new Error(error.message || 'Failed to update profile');
      }

      console.log('Profile updated successfully:', data);

      toast({ title: "Success", description: "Profile updated successfully!" });
      setShowProfileDialog(false);
      setAvatarFile(null);
      setAvatarPreview(null);
      
      // Refresh the page to update the UI
      setTimeout(() => {
        window.location.reload();
      }, 1000);
    } catch (error: any) {
      console.error('Error updating profile:', error);
      toast({ 
        title: "Error", 
        description: error.message || "Failed to update profile. Please try again.", 
        variant: "destructive" 
      });
    } finally {
      setIsUpdating(false);
    }
  };

  const handleRedeemAdminCode = async () => {
    if (!adminCode.trim()) {
      toast({ title: "Error", description: "Please enter an admin code", variant: "destructive" });
      return;
    }

    if (!user) {
      toast({ title: "Error", description: "User not found", variant: "destructive" });
      return;
    }

    setIsUpdating(true);
    try {
      console.log('Redeeming admin code:', adminCode.trim());

      // Check if the admin code exists and is not used
      const { data: adminKey, error: checkError } = await supabase
        .from('admin_keys')
        .select('*')
        .eq('key_code', adminCode.trim())
        .eq('is_used', false)
        .maybeSingle();

      if (checkError) {
        console.error('Error checking admin key:', checkError);
        throw new Error('Failed to validate admin code');
      }

      if (!adminKey) {
        throw new Error('Invalid or already used admin code');
      }

      console.log('Admin key found:', adminKey);

      // Mark the admin key as used
      const { error: updateKeyError } = await supabase
        .from('admin_keys')
        .update({
          is_used: true,
          used_at: new Date().toISOString(),
          used_by: user.id
        })
        .eq('id', adminKey.id);

      if (updateKeyError) {
        console.error('Error updating admin key:', updateKeyError);
        throw new Error('Failed to update admin key');
      }

      // Update user profile to admin
      const { data: updatedProfile, error: updateProfileError } = await supabase
        .from('user_profiles')
        .update({ is_admin: true })
        .eq('user_id', user.id)
        .select()
        .single();

      if (updateProfileError) {
        console.error('Error updating user profile:', updateProfileError);
        throw new Error('Failed to grant admin access');
      }

      console.log('Admin access granted:', updatedProfile);

      toast({ title: "Success", description: "Admin access granted successfully!" });
      setAdminCode('');
      setShowProfileDialog(false);
      
      // Refresh the page to update auth state
      setTimeout(() => {
        window.location.reload();
      }, 1000);
    } catch (error: any) {
      console.error('Error redeeming admin code:', error);
      toast({ 
        title: "Error", 
        description: error.message || "Failed to redeem admin code. Please try again.", 
        variant: "destructive" 
      });
    } finally {
      setIsUpdating(false);
    }
  };

  const handleChangePassword = async () => {
    if (newPassword !== confirmPassword) {
      toast({ title: "Error", description: "Passwords don't match", variant: "destructive" });
      return;
    }

    if (newPassword.length < 6) {
      toast({ title: "Error", description: "Password must be at least 6 characters", variant: "destructive" });
      return;
    }

    setIsUpdating(true);
    try {
      const { error } = await supabase.auth.updateUser({
        password: newPassword
      });

      if (error) throw error;

      toast({ title: "Success", description: "Password updated successfully!" });
      setShowPasswordDialog(false);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error: any) {
      console.error('Error updating password:', error);
      toast({ 
        title: "Error", 
        description: error.message || "Failed to update password", 
        variant: "destructive" 
      });
    } finally {
      setIsUpdating(false);
    }
  };

  if (!user) return null;

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Avatar className="h-8 w-8 cursor-pointer">
            <AvatarImage src={user.profile?.avatar_url} />
            <AvatarFallback className="bg-primary text-primary-foreground text-sm">
              {user.profile?.username?.[0]?.toUpperCase() || 'U'}
            </AvatarFallback>
          </Avatar>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56 bg-card border-border">
          <DropdownMenuItem onClick={() => setShowProfileDialog(true)} className="cursor-pointer">
            <User className="mr-2 h-4 w-4" />
            Edit Profile
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setShowPasswordDialog(true)} className="cursor-pointer">
            <Settings className="mr-2 h-4 w-4" />
            Change Password
          </DropdownMenuItem>
          {user.profile?.is_admin && (
            <DropdownMenuItem asChild>
              <Link to="/admin" className="cursor-pointer">
                <Users className="mr-2 h-4 w-4" />
                Admin Panel
              </Link>
            </DropdownMenuItem>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={onSignOut} className="cursor-pointer text-destructive">
            <LogOut className="mr-2 h-4 w-4" />
            Sign Out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Profile Edit Dialog */}
      <Dialog open={showProfileDialog} onOpenChange={setShowProfileDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Profile</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-center space-x-4">
              <Avatar className="h-16 w-16">
                <AvatarImage src={avatarPreview || user.profile?.avatar_url} />
                <AvatarFallback className="bg-primary text-primary-foreground">
                  {user.profile?.username?.[0]?.toUpperCase() || 'U'}
                </AvatarFallback>
              </Avatar>
              <div>
                <Label htmlFor="avatar-upload" className="cursor-pointer">
                  <Button variant="outline" size="sm" asChild disabled={isUpdating}>
                    <span>
                      <Upload className="mr-2 h-4 w-4" />
                      Upload Photo
                    </span>
                  </Button>
                </Label>
                <input
                  id="avatar-upload"
                  type="file"
                  accept="image/*"
                  onChange={handleAvatarChange}
                  className="hidden"
                  disabled={isUpdating}
                />
              </div>
            </div>
            
            <div>
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                disabled={isUpdating}
              />
            </div>
            
            <div>
              <Label htmlFor="bio">Bio</Label>
              <Input
                id="bio"
                value={bio}
                onChange={(e) => setBio(e.target.value)}
                placeholder="Tell us about yourself"
                disabled={isUpdating}
              />
            </div>

            {/* Admin Code Section */}
            {user.profile?.is_admin ? (
              <div className="p-3 bg-gradient-to-r from-yellow-500/10 to-orange-500/10 border border-yellow-500/30 rounded-lg">
                <div className="flex items-center space-x-2">
                  <Shield className="h-5 w-5 text-yellow-400" />
                  <span className="text-yellow-300 font-medium">You are an admin</span>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  You have administrative privileges and can access the admin panel.
                </p>
              </div>
            ) : (
              <div>
                <Label htmlFor="admin-code">Admin Code (Optional)</Label>
                <div className="flex space-x-2">
                  <Input
                    id="admin-code"
                    value={adminCode}
                    onChange={(e) => setAdminCode(e.target.value)}
                    placeholder="Enter admin code for admin access"
                    disabled={isUpdating}
                  />
                  <Button 
                    variant="outline" 
                    onClick={handleRedeemAdminCode}
                    disabled={isUpdating || !adminCode.trim()}
                  >
                    <Shield className="mr-1 h-4 w-4" />
                    {isUpdating ? 'Redeeming...' : 'Redeem'}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Enter a valid admin code to gain administrative privileges.
                </p>
              </div>
            )}

            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setShowProfileDialog(false)} disabled={isUpdating}>
                Cancel
              </Button>
              <Button onClick={handleUpdateProfile} disabled={isUpdating}>
                {isUpdating ? 'Updating...' : 'Update Profile'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Password Change Dialog */}
      <Dialog open={showPasswordDialog} onOpenChange={setShowPasswordDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Change Password</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="new-password">New Password</Label>
              <Input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
                disabled={isUpdating}
              />
            </div>
            
            <div>
              <Label htmlFor="confirm-password">Confirm Password</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                disabled={isUpdating}
              />
            </div>

            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setShowPasswordDialog(false)} disabled={isUpdating}>
                Cancel
              </Button>
              <Button onClick={handleChangePassword} disabled={isUpdating}>
                {isUpdating ? 'Updating...' : 'Update Password'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
};