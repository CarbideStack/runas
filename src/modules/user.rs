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

use super::error::Error;

use std::{
    ffi::CString,
    cell::{
        RefCell,
        Ref
    }
};

use nix::unistd::{
    User as CUser, 
    Group as CGroup,
    Uid as CUid,
    Gid as CGid,
    getuid,
    getgrouplist
};

/**
 * Represents a system group, including name and numeric ID.
 */
pub struct Group {
    pub(in self) gid: CGid,
    pub(in self) name: String
}

/**
 * Represents a system user, including name, UID, and primary group ID.
 */
pub struct User {
    pub(in self) uid: CUid,
    pub(in self) gid: CGid,
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
    pub(in self) group_list: RefCell<Option<Vec<CGid>>>
}

/**
 *
 */
#[allow(dead_code)]
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
    pub fn uid(&self) -> CUid { self.uid }
    
    /**
     * Return the user primary group ID
     */
    pub fn gid(&self) -> CGid { self.gid }

    /**
     * Create a user from a name or UID string.
     *
     * Accepts either a username (e.g., `"bob"`) or a numeric UID (e.g., `"1000"`).
     * Validates the entry against the system database and returns `Ok(User)` if found.
     */
    pub fn from(user: &str) -> Result<Option<Self>, Error> {
        let lookup_uid = |s: &str| -> Result<Option<CUser>, Error> {
            Ok(CUser::from_uid(CUid::from_raw(s.parse()?))?)
        };

        let info = if let Some(rest) = user.strip_prefix('#') {
            lookup_uid(rest)?

        } else if user.chars().all(char::is_numeric) {
            match CUser::from_name(user)? {
                Some(info) => Some(info),
                None => lookup_uid(user)?,
            }

        } else {
            CUser::from_name(user)?
        };

        if let Some(info) = info {
            return Self::from_uid(info.uid);
        }

        return Ok(None);
    }

    /**
     * Create a user from a UID.
     */
    pub fn from_uid(uid: CUid) -> Result<Option<Self>, Error> {
        if let Some(info) = CUser::from_uid(uid)? {
            return Ok(Some( 
                User {
                    gid: info.gid,
                    uid: info.uid,
                    name: info.name,
                    
                    home: info.dir.into_os_string()
                                    .into_string()
                                    .map_err(|_| Error::StaticMessage("user home path is not valid UTF-8"))?,
                                    
                    shell: info.shell.into_os_string()
                                    .into_string()
                                    .map_err(|_| Error::StaticMessage("user shell path is not valid UTF-8"))?,
                } 
           ));
        }
        
        return Ok(None);
    }
}

/**
 *
 */
#[allow(dead_code)]
impl Group {
    /**
     * Return the user name
     */
    pub fn name(&self) -> &str { &self.name }
    
    /**
     * Return the user primary group ID
     */
    pub fn gid(&self) -> CGid { self.gid }
    
    /**
     * Create a group from a name or GID string.
     *
     * Accepts either a group name or a numeric GID.
     * Validates the entry against the system database and returns `Some(Group)` if found.
     */
    pub fn from(group: &str) -> Result<Option<Self>, Error> {
        let lookup_gid = |s: &str| -> Result<Option<CGroup>, Error> {
            Ok(CGroup::from_gid(CGid::from_raw(s.parse()?))?)
        };

        let info = if let Some(rest) = group.strip_prefix('#') {
            lookup_gid(rest)?

        } else if group.chars().all(char::is_numeric) {
            match CGroup::from_name(group)? {
                Some(info) => Some(info),
                None => lookup_gid(group)?,
            }

        } else {
            CGroup::from_name(group)?
        };

        if let Some(info) = info {
            return Ok(Some( 
                Group { 
                    gid: info.gid,
                    name: info.name 
                } 
            ));
        }

        return Ok(None);
    }

    /**
     * Create a group from a name or GID string.
     *
     * Accepts either a group name or a numeric GID.
     * Validates the entry against the system database and returns `Some(Group)` if found.
     */
    pub fn from_gid(gid: CGid) -> Result<Option<Self>, Error> {
        if let Some(info) = CGroup::from_gid(gid)? {
            return Ok(Some(
                Group {
                    gid: info.gid,
                    name: info.name
                }
            ));
        }
        
        return Ok(None);
    }
}

/**
 *
 */
#[allow(dead_code)]
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
    pub fn uid(&self) -> CUid { self.user.uid }
    
    /**
     * Return the user group ID
     */
    pub fn gid(&self) -> CGid { self.group.gid }

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
    pub fn current() -> Result<Option<Self>, Error> {
        Self::from_uid(getuid())
    }
    
    /**
     * Construct a new `Account` from a username or UID string.
     *
     * Looks up both user and primary group entries and combines them into a full `Account`.
     */
    pub fn from(user: &str) -> Result<Option<Self>, Error> {
        let Some(user) = User::from(user)? else {
            return Ok(None);
        };

        let Some(group) = Group::from_gid(user.gid())? else {
            return Ok(None);
        };

        Ok(Some(Account {
            user,
            group,
            group_list: RefCell::new(None),
        }))
    }

    /**
     *
     */
    pub fn from_uid(uid: CUid) -> Result<Option<Self>, Error> {
        let Some(user) = User::from_uid(uid)? else {
            return Ok(None);
        };

        let Some(group) = Group::from_gid(user.gid())? else {
            return Ok(None);
        };

        Ok(Some(Account {
            user,
            group,
            group_list: RefCell::new(None),
        }))
    }
    
    /**
     * Get a list of all Gid's that this account is a member of.
     */
    pub fn group_list(&self) -> Result<Ref<'_, Vec<CGid>>, Error> {
        if self.group_list.borrow().is_none() {
            let username = CString::new(self.user.name.as_str())?;
            let groups = getgrouplist(username.as_c_str(), self.user.gid)?;

            *self.group_list.borrow_mut() = Some(groups);
        }

        Ok(Ref::map(
            self.group_list.borrow(),
            |opt| opt.as_ref().unwrap(),
        ))
    }
    
    /**
     * Check whether this account is a member of the specified group.
     */
    pub fn is_member(&self, group: &Group) -> Result<bool, Error> {
        // Root belongs to everything
        if self.user.uid.is_root() {
            return Ok(true);
        }

        let list = self.group_list()?;

        Ok(list.iter().any(|gid| *gid == group.gid()))
    }
}
