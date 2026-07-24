// Copyright (c) 2024 Daniel Bergløv
// 
// Permission is hereby granted, free of charge, to any person obtaining a 
// copy of this software and associated documentation files (the "Software"), 
// to deal in the Software without restriction, including without limitation 
// the rights to use, copy, modify, merge, publish, distribute, sublicense, 
// and/or sell copies of the Software, and to permit persons to whom the 
// Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE.

/**
 * User, Group, and Account abstractions for system identity management.
 *
 * This module provides safe Rust wrappers around POSIX user and group database
 * access, integrating `libc` and `nix::unistd` to retrieve and verify account
 * information. It defines three simple structs:
 *
 *  - `User`: represents a system user (name, UID, primary GID)
 *  - `Group`: represents a system group (name, GID)
 *  - `Account`: a composite of `User` and primary `Group`
 *
 * These structures are used throughout `runas` to represent both the invoking
 * and target user identities during authentication and privilege switching.
 * ```
 */

use crate::shared::*;
use crate::errx;
use std::ffi::CString;

use std::cell::{
    RefCell,
    Ref
};

use nix::unistd::{
    User as C_User, 
    Group as C_Group,
    Uid as C_Uid,
    Gid as C_Gid,
    getuid,
    getgrouplist
};

/**
 * Represents a system group, including name and numeric ID.
 */
pub struct Group {
    pub(in self) gid: C_Gid,
    pub(in self) name: String
}

/**
 * Represents a system user, including name, UID, and primary group ID.
 */
pub struct User {
    pub(in self) uid: C_Uid,
    pub(in self) gid: C_Gid,
    pub(in self) name: String,
    pub(in self) home: String,
    pub(in self) shell: String,
}

/**
 * Represents a combined user and group account (primary identity).
 */
pub struct Account {
    pub(in self) user: User,
    pub(in self) group: Group,
    pub(in self) group_list: RefCell<Option<Vec<C_Gid>>>
}

/**
 *
 */
impl User {
    /**
     *
     */
    pub fn is_root(&self) -> bool { self.uid.is_root() }

    /**
     * Return the user shell
     */
    pub fn shell(&self) -> &str { &self.shell }

    /**
     * Return the user home dir
     */
    pub fn home(&self) -> &str { &self.home }

    /**
     * Return the user name
     */
    pub fn name(&self) -> &str { &self.name }
    
    /**
     * Return the user ID
     */
    pub fn uid(&self) -> C_Uid { self.uid }
    
    /**
     * Return the user primary group ID
     */
    pub fn gid(&self) -> C_Gid { self.gid }

    /**
     * Create a user from a name or UID string.
     *
     * Accepts either a username (e.g., `"bob"`) or a numeric UID (e.g., `"1000"`).
     * Validates the entry against the system database and returns `Some(User)` if found.
     *
     * Aborts the process with `errx!()` if the system user database cannot be queried.
     */
    pub fn from(user: &str) -> Option<Self> {
        let mut uinfo: Option<C_User>;

        if let Some(rest) = user.strip_prefix('#') {
            // Explicit numeric ID (forced with '#')
            let parsed_uid = rest.parse::<u32>().unwrap_or_else(|_e| { errx!(1, MSG_PARSE_NUM); });
            let uid = C_Uid::from_raw(parsed_uid);

            // Validate that this UID exists
            uinfo = C_User::from_uid(uid).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });

        } else if user.chars().all(char::is_numeric) {
            // Numeric-looking name — try name first, then fallback to UID lookup
            uinfo = C_User::from_name(user).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });

            if uinfo.is_none() {
                let parsed_uid = user.parse::<u32>().unwrap_or_else(|_e| { errx!(1, MSG_PARSE_NUM); });
                let uid = C_Uid::from_raw(parsed_uid);
                
                uinfo = C_User::from_uid(uid).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
            }

        } else {
            // Normal username
            uinfo = C_User::from_name(user).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
        }
        
        if let Some(uinfo) = uinfo {
            return Some( 
                User {
                    gid: uinfo.gid,
                    uid: uinfo.uid,
                    name: uinfo.name,
                    
                    home: uinfo.dir.into_os_string()
                                    .into_string()
                                    .unwrap_or_else(|_e| { errx!(1, "Invalid UTF-8 in user home path"); }),
                                    
                    shell: uinfo.shell.into_os_string()
                                    .into_string()
                                    .unwrap_or_else(|_e| { errx!(1, "Invalid UTF-8 in user home path"); })
                } 
           );
        }
        
        None
    }
}

/**
 *
 */
impl Group {
    /**
     * Return the user name
     */
    pub fn name(&self) -> &str { &self.name }
    
    /**
     * Return the user primary group ID
     */
    pub fn gid(&self) -> C_Gid { self.gid }
    
    /**
     * Create a group from a name or GID string.
     *
     * Accepts either a group name or a numeric GID.
     * Validates the entry against the system database and returns `Some(Group)` if found.
     */
    pub fn from(group: &str) -> Option<Self> {
        let mut ginfo: Option<C_Group>;
        
        if let Some(rest) = group.strip_prefix('#') {
            // Explicit numeric ID (forced with '#')
            let parsed_gid = rest.parse::<u32>().unwrap_or_else(|_e| { errx!(1, MSG_PARSE_NUM); });
            let gid = C_Gid::from_raw(parsed_gid);

            // Validate that this GID exists
            ginfo = C_Group::from_gid(gid).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });

        } else if group.chars().all(char::is_numeric) {
            // Numeric-looking name — try name first, then fallback to GID lookup
            ginfo = C_Group::from_name(group).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });

            if ginfo.is_none() {
                let parsed_gid = group.parse::<u32>().unwrap_or_else(|_e| { errx!(1, MSG_PARSE_NUM); });
                let gid = C_Gid::from_raw(parsed_gid);
                
                ginfo = C_Group::from_gid(gid).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
            }
        
        } else {
            ginfo = C_Group::from_name(group).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
        }
        
        if let Some(ginfo) = ginfo {
            return Some( 
                Group { 
                    gid: ginfo.gid,
                    name: ginfo.name 
                } 
           );
        }
        
        None
    }
}

/**
 *
 */
impl Account {
    /**
     *
     */
    pub fn is_root(&self) -> bool { self.user.uid.is_root() }

    /**
     * Return the user shell
     */
    pub fn shell(&self) -> &str { &self.user.shell }

    /**
     * Return the user home dir
     */
    pub fn home(&self) -> &str { &self.user.home }

    /**
     * Return the user name
     */
    pub fn name(&self) -> &str { &self.user.name }
    
    /**
     * Return the user ID
     */
    pub fn uid(&self) -> C_Uid { self.user.uid }
    
    /**
     * Return the user group ID
     */
    pub fn gid(&self) -> C_Gid { self.group.gid }

    /**
     * Return the user object
     */
    pub fn user(&self) -> &User { &self.user }
    
    /**
     * Return the group object
     */
    pub fn group(&self) -> &Group { &self.group }
    
    /**
     *
     */
    pub fn set_user(&mut self, user: User) {
        self.user = user;
    }
    
    /**
     *
     */
    pub fn set_group(&mut self, group: Group) {
        self.group = group;
    }

    /**
     * Get an instance of the current executing account
     */
    pub fn current() -> Option<Self> {
        let uid = getuid().as_raw().to_string();
        Self::from(&uid)
    }
    
    /**
     * Construct a new `Account` from a username or UID string.
     *
     * Looks up both user and primary group entries and combines them into a full `Account`.
     */
    pub fn from(user: &str) -> Option<Self> {
        if let Some(user) = User::from(user) {
            if let Some(group) = Group::from(&user.gid.to_string()) { 
                return Some(
                    Account {
                        user: user, 
                        group: group, 
                        group_list: RefCell::new(None)
                    }
                );
            }
        }
        
        None
    }
    
    /**
     * Get a list of all Gid's that this account is a member of.
     */
    pub fn group_list(&self) -> Ref<'_, Vec<C_Gid>> {
        if self.group_list.borrow().is_none() {
            let username = CString::new(self.user.name.as_str())
                .unwrap_or_else(|_| {
                    errx!(1, MSG_PARSE_CSTRING);
                });

            let groups = getgrouplist(username.as_c_str(), self.user.gid)
                .unwrap_or_else(|error| {
                    errx!(
                        1,
                        "Failed to retrieve groups for {}: {}",
                        self.user.name,
                        error
                    );
                });
            
            *self.group_list.borrow_mut() = Some(groups);
        }
        
        Ref::map(self.group_list.borrow(), |opt| opt.as_ref().unwrap())
    }
    
    /**
     * Check whether this account is a member of the specified group.
     */
    pub fn is_member(&self, group: &Group) -> bool {
        // Root belongs to everything
        if self.user.uid.is_root() {
            return true;
        }
        
        let list: Ref<'_, Vec<C_Gid>> = self.group_list();
        
        for gid in &*list {
            if *gid == group.gid() {
                return true;
            }
        }
        
        false
    }
}

